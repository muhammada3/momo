# Data Anonymizer

This is a simple desktop application to help you anonymize sensitive data in your logs or other texts. It masks common sensitive information like email addresses, phone numbers, and IP addresses.

## Building the Application (Recommended)

To create a standalone executable that you can run without installing Python or any dependencies, you can use `pyinstaller`.

1.  **Install `pyinstaller`:**
    ```sh
    pip install pyinstaller
    ```

2.  **Run `pyinstaller`:**
    From the root of the project, run the following command:
    ```sh
    pyinstaller main.spec
    ```

3.  **Run the executable:**
    The executable file will be located in the `dist` directory. You can run it from there.

## Running from Source

If you have Python installed, you can also run the application directly from the source code.

1.  **Navigate to the `app` directory:**
    ```sh
    cd anonymizer/app
    ```

2.  **Run the application:**
    ```sh
    python3 main.py
    ```

    This will open a window with a simple user interface.

## How to Use

1.  Paste your text into the input box.
2.  Click the "Anonymize" button.
3.  The anonymized text will appear in the output box.
4.  You can then copy the anonymized text to your clipboard using the "Copy to Clipboard" button.
