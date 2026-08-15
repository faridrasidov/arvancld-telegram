"""Application bootstrap for polling the Telegram Bot API."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress

from dotenv import load_dotenv
from telebot.async_telebot import AsyncTeleBot

from arvancld_telegram.config import ConfigurationError, Settings, configure_logging
from arvancld_telegram.controller import BotController
from arvancld_telegram.gateway import ArvanCloudGateway

logger = logging.getLogger(__name__)


async def run(settings: Settings | None = None) -> None:
    """Validate dependencies, register handlers, and poll until shutdown."""

    load_dotenv()
    resolved = settings or Settings.from_env()
    configure_logging(resolved.log_level)

    bot = AsyncTeleBot(resolved.telegram_bot_token, parse_mode="HTML")
    gateway = ArvanCloudGateway(resolved)
    controller = BotController(bot, resolved, gateway)
    polling: asyncio.Task[None] | None = None
    try:
        controller.register_handlers()
        await bot.get_me()
        await gateway.start()
        await bot.skip_updates()
        logger.info("starting Telegram long polling")
        polling = asyncio.create_task(
            bot.infinity_polling(
                skip_pending=False,
                timeout=30,
                request_timeout=35,
                allowed_updates=["message", "callback_query"],
            )
        )
        await asyncio.sleep(0)
        await controller.notify_auth_required()
        await polling
    finally:
        if polling is not None and not polling.done():
            polling.cancel()
            with suppress(asyncio.CancelledError):
                await polling
        await gateway.close()
        close_session = getattr(bot, "close_session", None)
        if close_session is not None:
            await close_session()


def main() -> None:
    """Console entry point."""

    try:
        asyncio.run(run())
    except ConfigurationError as exc:
        raise SystemExit(f"Configuration error: {exc}") from None
    except KeyboardInterrupt:
        pass
