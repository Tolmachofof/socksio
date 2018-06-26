from argparse import ArgumentParser
import asyncio
import logging

import uvloop

from socksio.server import create_server


def parse_args():
    parser = ArgumentParser(prog='aiosocks')
    parser.add_argument('--host', dest='host', type=str, default='127.0.0.1')
    parser.add_argument('--port', dest='port', type=int, default=1080)
    return parser.parse_args()


def create_logger():
    logger = logging.getLogger('socksio')
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


if __name__ == '__main__':
    args = parse_args()
    logger = create_logger()
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    loop.create_task(create_server(args.host, args.port))
    try:
        loop.run_forever()
    finally:
        logger.info('Proxy has been stopped.')
