# 🧠 LLM-Phish Buster — Setup & Installation Guide

Follow the steps below to set up the project environment, install dependencies, and run the application locally.

---

## ⚙️ 1. Prerequisites

Before starting, make sure you have the following installed on your system:

* **Python 3.8+**
* **pip** (Python package manager)
* **Git** (for cloning the repository)
* **Virtual environment support** (comes pre-installed with Python 3.8+)

---

## 📂 2. Clone the Repository

```bash
# Clone the GitHub repository
git clone https://github.com/AnandaSriKaushalB/LLM-PHISHBUSTER-chrome-extension-

# Navigate into the project folder
cd LLM-Phish-Buster
```

---

## 🧩 3. Create a Virtual Environment

It’s recommended to use a virtual environment to isolate project dependencies.

```bash
# Create a virtual environment named .venv
python -m venv .venv
```

Activate the environment:

* **Windows (Command Prompt):**

  ```bash
  .venv\Scripts\activate
  ```

* **Windows (PowerShell):**

  ```bash
  .venv\Scripts\Activate.ps1
  ```

* **macOS/Linux:**

  ```bash
  source .venv/bin/activate
  ```

> ✅ When activated, your terminal prompt will show `(.venv)` at the start.

---

## 📦 4. Install Dependencies

With the virtual environment active, install all required packages using the provided `requirements.txt` file.

```bash
pip install -r requirements.txt
```

> This command automatically installs every library your project needs — such as `Flask`, `torch`, `sentence-transformers`, `scikit-learn`, etc.

---

## 🧠 5. Running the Application

Once installation is complete, you can start your Flask app by running:

```bash
python app.py
```

If everything is configured correctly, you should see output similar to:

```
 * Running on http://127.0.0.1:5000
```

Now open your web browser and visit [http://127.0.0.1:5000](http://127.0.0.1:5000) to access the app.

---

## 🔍 6. Deactivating the Virtual Environment

When you’re done working on the project, deactivate the virtual environment using:

```bash
deactivate
```

This returns you to the global Python environment.

---

## 🧰 7. (Optional) Updating Requirements

If you install new libraries while developing, update `requirements.txt` with:

```bash
pip freeze > requirements.txt
```

This keeps the dependencies list in sync for other collaborators.

---

## 💡 8. Common Issues

| Problem              | Possible Solution                           |
| -------------------- | ------------------------------------------- |
| `pip` not recognized | Add Python to PATH or reinstall Python      |
| Flask not found      | Ensure you activated `.venv` before running |
| Port already in use  | Run with `python app.py --port 8000`        |

---

Would you like me to also include a **section for environment variables** (for example, if your app needs API keys or model paths) and a **“Run with VS Code”** tip section? It makes your README even more developer-friendly.
