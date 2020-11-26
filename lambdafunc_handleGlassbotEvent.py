import os
import logging
import urllib.request
import urllib.parse
import json
import re
import time
import hmac
import hashlib

# Grab the Bot OAuth token from the environment.
BOT_TOKEN = os.environ["BOT_TOKEN"]
BOT_SIGNING_SECRET = os.environ["BOT_SIGNING_SECRET"]
USERID_TO_MENTION = os.environ["USERID_TO_MENTION"]
ROBOT_ANNOUNCE_TEXT = "<@" + USERID_TO_MENTION + ">. Glassware."

# Define the URL of the targeted Slack API resource.
# We'll send our replies there.
SLACK_URL = "https://slack.com/api/chat.postMessage"

def format_dict(d):
    vals = list(d.values())
    return "={},".join(d.keys()).format(*vals) + "={}".format(vals[-1])


def lambda_handler(event, context):

    logging.info(json.dumps(event))

    # Ive setup mapping in api-gateway to provide body in body-json
    # along with the headers, and raw body in body-raw (escaped)

    if "body-json" in event:
        data = event["body-json"]
        if ( "body-raw" in event
              and "params" in event
              and "header" in event["params"]
              and "X-Slack-Request-Timestamp" in event["params"]["header"] ):

            rawbody = event["body-raw"]
            headers = event["params"]["header"]
            timestamp = headers["X-Slack-Request-Timestamp"]
            signature = headers["X-Slack-Signature"]

            if signature.startswith("v0="):
                sig_basestring = "v0:" + timestamp + ":" + rawbody
                #logging.warn("sig_basestring: " + sig_basestring)

            epoch_time = int(time.time())
            timestamp = int(timestamp)

            if abs(epoch_time - timestamp) > 60 * 5:
            # The request timestamp is more than five minutes from local time.
            # It could be a replay attack, so let's ignore it.
                return

            messagebytes = bytes(sig_basestring, 'utf-8')
            secretbytes = bytes(BOT_SIGNING_SECRET, 'utf-8')
            digest = hmac.new(secretbytes,messagebytes,hashlib.sha256).hexdigest()
            my_signature = 'v0=' + digest

            if ( signature != my_signature ):
                return

            #logging.warn("signature: " + signature)
            #logging.warn("my_signature: " + my_signature)

    else:
        data = event

    # Needed for successful registration
    if "challenge" in data:
        return data["challenge"]

    announce_glassware = False

    # Validate data contains event, otherwise return a 4xx code
    
    if not "event" in data:
        return "400 Bad Request"

    # Grab the Slack event data.
    slack_event = data['event']

    thread_ts = 0

    # Search for glassware mentions in normal messages from people
    if ( slack_event["type"] == "message"
         and "subtype" not in slack_event
         and "text" in slack_event
         and re.search('glassware', slack_event["text"], re.IGNORECASE) ):
            announce_glassware = True
            if  "thread_ts" in slack_event:
                thread_ts = slack_event["thread_ts"]


    # Search for glassware mentions in unfurled content
    if ( slack_event["type"] == "message"
        and "subtype" in slack_event
        and slack_event["subtype"] == "message_changed"
        and "message" in slack_event
        and "attachments" in slack_event["message"] ):

            message = slack_event["message"]
            if  "thread_ts" in message:
                thread_ts = message["thread_ts"]

            attachments = message["attachments"]
            for attachment in attachments:
                if ( "text" in attachment
                    and re.search('glassware', attachment["text"], re.IGNORECASE)
                    ):
                        announce_glassware = True

    if announce_glassware:
        # Get the ID of the channel where the message was posted.
        channel_id = slack_event["channel"]

        # seedData = (
        #         ("token", BOT_TOKEN),
        #         ("channel", channel_id),
        #         ("text", MATT_GLASSWARE)
        #     )

        data = { 'token': BOT_TOKEN, 'channel' : channel_id, 'text': ROBOT_ANNOUNCE_TEXT}

        # if the message we are responding to was in a thread
        # provide the thread_ts in our post to attach to the parent thread
        if thread_ts != 0:
            data["thread_ts"] = thread_ts

        data = urllib.parse.urlencode(data)
        data = data.encode("ascii")
             # Construct the HTTP request that will be sent to the Slack API.
        request = urllib.request.Request(
            SLACK_URL,
            data=data,
            method="POST"
        )
        # Add a header mentioning that the text is URL-encoded.
        request.add_header(
            "Content-Type",
            "application/x-www-form-urlencoded"
        )

        # Fire off the request!
        urllib.request.urlopen(request).read()

    # Everything went fine.
    return "200 OK"


