# /// script
# dependencies = [
#   "atproto==0.0.62",
#   "pydantic==2.12.0",
# ]
# ///

# Usage:
# uv run firehose_to_ndjson.py workload-id-1337.bsky.social | jq -r '.record.text'
# uv run -m src.workload_identity_oauth_reverse_proxy.firehose_to_ndjson workload-id-1337.bsky.social | jq -r '.record.text'

import asyncio
import argparse
import json
import logging
import signal
import sys
import time
import typing as t
from functools import partial
from pydantic import BaseModel, Field

from atproto import (
    AsyncClient,
    AsyncFirehoseSubscribeReposClient,
    CAR,
    AsyncIdResolver,
    firehose_models,
    models,
    parse_subscribe_repos_message,
)
from atproto.exceptions import FirehoseError
from atproto_client.models.utils import get_or_create

# --- Application Context ---
# A Pydantic model to hold the application's state, avoiding global variables.
class AppContext(BaseModel):
    did_to_handle_map: t.Dict[str, str] = Field(default_factory=dict)
    target_dids: t.Set[str] = Field(default_factory=set)


# --- Logging Setup ---
# Configure logging to output to stderr, keeping stdout clean for NDJSON.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr,
)


def measure_events_per_second(func: t.Callable) -> t.Callable:
    """Decorator to measure and log the rate of firehose events."""
    async def wrapper(*args, **kwargs) -> t.Any:
        wrapper.calls += 1
        cur_time = time.time()
        elapsed = cur_time - wrapper.start_time

        # Log every 5 seconds
        if elapsed >= 5.0:
            rate = wrapper.calls / elapsed
            logging.info(f"Network load: {rate:.2f} events/second")
            wrapper.start_time = cur_time
            wrapper.calls = 0

        return await func(*args, **kwargs)

    wrapper.calls = 0
    wrapper.start_time = time.time()
    return wrapper


def _get_operations_from_commit(commit: models.ComAtprotoSyncSubscribeRepos.Commit) -> t.Iterator[dict]:
    """Generator that yields structured data for each operation in a commit."""
    car = CAR.from_bytes(commit.blocks)
    for op in commit.ops:
        uri = f'at://{commit.repo}/{op.path}'
        collection = op.path.split('/')[0]
        rkey = op.path.split('/')[1]

        operation_data = {
            "action": op.action,
            "collection": collection,
            "rkey": rkey,
            "uri": uri,
        }

        if op.action == 'create':
            if not op.cid or not car.blocks:
                continue
            
            record_raw_data = car.blocks.get(op.cid)
            if not record_raw_data:
                continue

            record = get_or_create(record_raw_data, strict=False)
            operation_data["record_type"] = getattr(record, '$type', 'unknown')
            operation_data["record"] = record_raw_data
            yield operation_data

        elif op.action == 'delete':
            yield operation_data


async def resolve_identifier(identifier: str) -> t.AsyncIterator[t.Tuple[str, str]]:
    """Resolves a handle to a DID or fetches the handle for a given DID."""
    resolver = AsyncIdResolver()
    results = []
    try:
        if identifier.startswith('did:'):
            did_document = await resolver.did.resolve(identifier)
            for handle in did_document.also_known_as:
                logging.info(f"Resolved handle {handle} to DID {identifier}")
                results.append((identifier, handle))
        else:
            did = await resolver.handle.resolve(identifier)
            logging.info(f"Resolved DID {did} to handle {identifier}")
            results.append((did, identifier))
    except Exception as e:
        logging.error(f"Could not resolve identifier '{identifier}': {e}")
        raise
    return results


@measure_events_per_second
async def on_message(ctx: AppContext, message: firehose_models.MessageFrame) -> None:
    """Asynchronous handler for firehose messages, decorated to measure event rate."""
    commit = parse_subscribe_repos_message(message)
    if not isinstance(commit, models.ComAtprotoSyncSubscribeRepos.Commit):
        return

    if commit.repo not in ctx.target_dids:
        return

    try:
        for operation in _get_operations_from_commit(commit):
            handle = ctx.did_to_handle_map.get(commit.repo, 'unknown.handle')
            output_event = {
                "repo": commit.repo,
                "handle": handle,
                "seq": commit.seq,
                "time": commit.time,
                **operation,  # Unpack operation data (action, collection, record, etc.)
            }
            sys.stdout.write(json.dumps(output_event) + '\n')
            sys.stdout.flush()
    except Exception as e:
        logging.error(f"Error processing commit seq {commit.seq} for {commit.repo}: {e}")


async def main() -> None:
    """Parses arguments, resolves identifiers, and starts the firehose client with graceful shutdown."""
    parser = argparse.ArgumentParser(description="Monitor Bluesky handles/DIDs and output new records as NDJSON.")
    parser.add_argument('identifiers', nargs='+', help="A list of handles (e.g., 'bsky.app') or DIDs to monitor.")
    args = parser.parse_args()

    app_context = AppContext()
    results = await asyncio.gather(*map(resolve_identifier, args.identifiers))
    
    for result in results:
        for did, handle in result:
            app_context.did_to_handle_map[did] = handle
            app_context.target_dids.add(did)

    if not app_context.target_dids:
        logging.error("No valid identifiers could be resolved. Exiting.")
        sys.exit(1)
        
    message_handler = partial(on_message, app_context)
    firehose_client = AsyncFirehoseSubscribeReposClient()

    # Set up graceful shutdown
    loop = asyncio.get_running_loop()
    stop_future = loop.create_future()
    loop.add_signal_handler(signal.SIGINT, stop_future.set_result, None)

    logging.info(f"Starting client to monitor {len(app_context.target_dids)} DIDs. Press Ctrl+C to stop.")
    
    firehose_task = asyncio.create_task(firehose_client.start(message_handler))

    try:
        await stop_future
        logging.info("Shutdown signal received...")
    except FirehoseError as e:
        logging.error(f"Firehose connection error: {e}. Is the relay running?")
    finally:
        logging.info("Stopping the firehose client.")
        await firehose_client.stop()
        # Ensure the background task is cancelled and awaited
        firehose_task.cancel()
        await asyncio.gather(firehose_task, return_exceptions=True)
        logging.info("Client stopped.")


if __name__ == "__main__":
    asyncio.run(main())

