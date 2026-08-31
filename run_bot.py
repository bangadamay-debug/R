import os
import asyncio

from app import telegram_app, BOT_TOKEN, start_command, callback_handler, message_handler
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters

async def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is missing")
    application = Application.builder().token(BOT_TOKEN).connect_timeout(30).read_timeout(30).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CallbackQueryHandler(callback_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    await application.initialize()
    await application.start()
    await application.updater.start_polling(drop_pending_updates=True)
    print("Telegram bot polling started.")
    try:
        await asyncio.Event().wait()
    finally:
        await application.updater.stop()
        await application.stop()
        await application.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
