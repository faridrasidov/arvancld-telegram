"""Application bootstrap for polling the Telegram Bot API."""

from __future__ import annotations

import asyncio
import importlib.metadata
import logging
import os
from contextlib import suppress

import arvancld
from arvancld.auth import AsyncAuthService
from dotenv import load_dotenv
from telebot.async_telebot import AsyncTeleBot

from arvancld_telegram.config import ConfigurationError, Settings, configure_logging
from arvancld_telegram.controller import BotController
from arvancld_telegram.gateway import ArvanCloudGateway

logger = logging.getLogger(__name__)


def log_sdk_provenance() -> None:
    """Log only immutable, non-secret SDK build provenance and capability data."""

    try:
        version = importlib.metadata.version("arvancld")
    except importlib.metadata.PackageNotFoundError:
        version = getattr(arvancld, "__version__", "unavailable")
    logger.info(
        "arvancld sdk version=%s sha=%s module=%s submit_totp=%s",
        version,
        os.environ.get("ARVANCLD_SDK_REF", "unavailable"),
        getattr(arvancld, "__file__", "unavailable"),
        hasattr(AsyncAuthService, "submit_totp"),
    )


async def run(settings: Settings | None = None) -> None:
    """Validate dependencies, register handlers, and poll until shutdown."""

    load_dotenv()
    resolved = settings or Settings.from_env()
    configure_logging(resolved.log_level)
    log_sdk_provenance()

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
