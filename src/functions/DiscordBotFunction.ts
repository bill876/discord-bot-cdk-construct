import {Context, Callback} from 'aws-lambda';
import {DiscordEventRequest, DiscordEventResponse} from '../types';
import {Lambda, SSM} from 'aws-sdk';
import {commandLambdaARN} from './constants/EnvironmentProps';
import {sign} from 'tweetnacl';

const lambda = new Lambda();

const BOT_USER_PUBLIC_KEY_PARAMETER_NAME = process.env.BOT_USER_PUBLIC_KEY_PARAMETER_NAME;
const ssm = new SSM({apiVersion: '2014-11-06'});
let _botUserPublicKey = '';

async function getBotUserPublicKey() {
  if (!_botUserPublicKey) {
    console.log('Public Key not cached, retrieving...');
    if (BOT_USER_PUBLIC_KEY_PARAMETER_NAME) {
      const response = await ssm.getParameter({ Name: BOT_USER_PUBLIC_KEY_PARAMETER_NAME }).promise();
      _botUserPublicKey = response.Parameter?.Value || '';
    }
  }
  return _botUserPublicKey;
}

/**
 * Handles incoming events from the Discord bot.
 * @param {DiscordEventRequest} event The incoming request to handle.
 * @param {Context} context The context this request was called with.
 * @param {Callback} callback A callback to handle the request.
 * @return {DiscordEventResponse} Returns a response to send back to Discord.
 */
export async function handler(
  event: DiscordEventRequest,
  context: Context,
  callback: Callback)
: Promise<DiscordEventResponse> {
  console.log(`Received event: ${JSON.stringify(event)}`);

  const verifyPromise = verifyEvent(event);

  if (event) {
    switch (event.jsonBody.type) {
      case 1:
        // Return pongs for pings
        if (await verifyPromise) {
          return {
            type: 1,
          };
        }
        break;
      case 2:
        // Actual input request
        const lambdaPromise = lambda.invoke({
          FunctionName: commandLambdaARN,
          Payload: JSON.stringify(event),
          InvocationType: 'Event',
        }).promise();
        if (await Promise.all([verifyPromise, lambdaPromise])) {
          console.log('Returning temporary response...');
          return {
            type: 5,
          };
        }
        break;
    }
  }

  throw new Error('[UNAUTHORIZED] invalid request signature');
}

/**
 * Verifies that an event coming from Discord is legitimate.
 * @param {DiscordEventRequest} event The event to verify from Discord.
 * @return {boolean} Returns true if the event was verified, false otherwise.
 */
export async function verifyEvent(event: DiscordEventRequest): Promise<boolean> {
  try {
    console.log('Getting Discord secrets...');
    const botUserPublicKey = await getBotUserPublicKey();
    console.log('Verifying incoming event...');
    const isVerified = sign.detached.verify(
        Buffer.from(event.timestamp + JSON.stringify(event.jsonBody)),
        Buffer.from(event.signature, 'hex'),
        Buffer.from(botUserPublicKey, 'hex'),
    );
    console.log('Returning verification results...');
    return isVerified;
  } catch (exception) {
    console.log(exception);
    return false;
  }
}
