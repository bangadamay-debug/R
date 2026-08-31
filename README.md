# Meesho Telegram Bot — GitHub + Temporary Free Web App

This setup uses **GitHub Actions for the Telegram bot** and a **free Render Web Service for the Mini App**.

## 1. Put the project on GitHub

Create a GitHub repository and upload the contents of this folder.

## 2. Deploy the Mini App on Render (temporary/free)

1. Create a free account at Render.
2. Create **New → Blueprint** (or a Web Service) from your GitHub repository.
3. Select the repository.
4. Render reads `render.yaml` and creates the web service.
5. After deployment, Render gives you an HTTPS address such as `https://your-service.onrender.com`.

The Render service has `RUN_BOT=0`, so it only hosts the web app and does **not** start Telegram polling.

## 3. Add the GitHub Actions secrets

GitHub → **Settings → Secrets and variables → Actions → New repository secret**:

- `BOT_TOKEN` = your BotFather token
- `WEBAPP_URL` = the exact HTTPS Render URL from step 2

Example value:
`https://your-service.onrender.com`

## 4. Start the Telegram bot

GitHub → **Actions → Run Meesho Telegram Bot → Run workflow**.

The workflow runs `run_bot.py`, so it starts Telegram polling without starting a second web server.

## 5. Test

Open your Telegram bot and send `/start`.
Press **🛍️ Open Shop**. Telegram should open the Render HTTPS Mini App.

## Important about the free Render plan

This is intended for testing/temporary use. Free web services can sleep when inactive, so the Mini App may take a little time to wake up. GitHub Actions jobs are also temporary and have runtime limits; this is not a permanent 24/7 hosting setup.

## Security

Never commit your BotFather token. Store it only in GitHub Actions Secrets and, if you decide to run the bot directly on Render later, use Render's secret environment variable instead.
