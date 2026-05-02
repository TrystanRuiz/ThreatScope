#!/bin/bash
cd "$(dirname "$0")"

if ! pgrep -x ollama > /dev/null; then
    open -a Ollama
    sleep 3
fi

source venv/bin/activate
streamlit run app/ui.py
