VENV_DIR=".sabre_venv"

## create if first time
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating '$VENV_DIR' virtual environment..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment '$VENV_DIR' found!"
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "Installing the following requirements from requirements.txt..."
cat requirements.txt
echo
pip install -v -r requirements.txt

read -p "Press Enter to continue..."
clear
export PS1="[verifier]$: "