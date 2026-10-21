"""Configure the authorized provider locally; never echo the secret."""
import getpass
import json
from pathlib import Path
import sys
import warnings

APP = Path(__file__).resolve().parents[1] / 'app'
sys.path.insert(0, str(APP))

def main():
    from api_credentials import save_key
    from lab import Settings
    template = json.loads(Path(__file__).with_name('settings.template.json').read_text(encoding='utf-8'))
    if '--gui' in sys.argv:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
        window = tk.Tk()
        window.withdraw()
        key = simpledialog.askstring('Mydex API',
            'Paratera API key\nhttps://llmapi.paratera.com/v1\nQwen3.8-Flash',
            show='*', parent=window)
        if key is None:
            window.destroy()
            return
    else:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            key = getpass.getpass('Paratera API key (hidden): ')
    save_key(APP / '.local/paratera-api-key.dpapi', template['api_base'], key)
    key = None
    settings = Settings(APP / '.local/settings.json')
    fields = ('provider', 'bot_name', 'model', 'api_base', 'api_mode',
              'api_credential', 'api_enable_thinking', 'api_key', 'conversation_enabled')
    settings.update({k: template[k] for k in fields} if settings.path.exists() else template)
    if '--gui' in sys.argv:
        messagebox.showinfo('Mydex API', 'Saved with Windows CurrentUser DPAPI.', parent=window)
        window.destroy()
    print('Provider configured locally. WeChat account/session enrollment is still required.')

if __name__ == '__main__':
    main()
