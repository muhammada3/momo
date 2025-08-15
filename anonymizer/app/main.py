import tkinter as tk
from tkinter import scrolledtext
from anonymizer import anonymize_text

class AnonymizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Data Anonymizer")

        # Input Text Area
        self.input_label = tk.Label(root, text="Paste your text here:")
        self.input_label.pack(pady=5)
        self.input_text = scrolledtext.ScrolledText(root, width=80, height=15, wrap=tk.WORD)
        self.input_text.pack(pady=5, padx=10)

        # Anonymize Button
        self.anonymize_button = tk.Button(root, text="Anonymize", command=self.anonymize)
        self.anonymize_button.pack(pady=5)

        # Output Text Area
        self.output_label = tk.Label(root, text="Anonymized text:")
        self.output_label.pack(pady=5)
        self.output_text = scrolledtext.ScrolledText(root, width=80, height=15, wrap=tk.WORD)
        self.output_text.pack(pady=5, padx=10)

        # Copy to Clipboard Button
        self.copy_button = tk.Button(root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(pady=5)

    def anonymize(self):
        input_data = self.input_text.get("1.0", tk.END)
        anonymized_data = anonymize_text(input_data)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", anonymized_data)

    def copy_to_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get("1.0", tk.END))
        self.root.update() # Now it stays on the clipboard after the window is closed

if __name__ == "__main__":
    root = tk.Tk()
    app = AnonymizerApp(root)
    root.mainloop()
