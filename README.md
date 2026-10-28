# Cup O' Cheese

A simple social feed inspired by Letterkenny. Register, log in, and post updates.
Domain: cupocheese.com

## Run locally

```bash
cd app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

## Features

- User registration and login (passwords hashed)
- Create posts
- View feed of recent posts
- Sessions for staying logged in

Database file `cupocheese.db` is created automatically on first run.
