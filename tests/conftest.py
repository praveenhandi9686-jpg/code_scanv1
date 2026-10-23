import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"   # app.py builds a module-level app on import
os.environ.pop("VERCEL", None)
