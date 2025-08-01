# URL Collector - Burp Suite Extension

The **URL Collector** is a Burp Suite extension that helps testers automatically and manually log important HTTP request data during penetration testing. This extension captures in-scope POST requests and GET requests **with URL parameters** from the **Proxy tab** and displays them in a structured, Excel-style GUI inside Burp.

## 🛠 Features

- ✅ **Automatic Logging** of:
  - In-scope POST requests
  - In-scope GET requests with parameters in the URL
  - Only from Proxy tab (ignores Repeater, Scanner, Intruder, etc.)
- ✅ **Manual Logging** via right-click context menu ("Send to URL Collector")
- ✅ **Toggle Button** to turn auto-logging ON/OFF
- ✅ **Clear Table** button to reset the table contents
- ✅ **Copy Button** for each row to easily export data to Excel
- ✅ Editable table with un-fixed column widths

---

## 📦 Table Columns

| Column Name     | Description                                        |
|-----------------|----------------------------------------------------|
| **Domain**      | Scheme and host (e.g., `https://example.com`)      |
| **Path**        | URI path and query string (if any)                 |
| **Method**      | HTTP method (GET/POST)                             |
| **No. of Params** | Number of parameters in the request              |
| **Logs Saved**  | Always set to `Yes`                                |
| **Tested**      | Placeholder column (can be used for status tracking) |
| **Autorize**    | Placeholder column (used for integrations or notes) |
| **Copy**        | A click-to-copy button for Excel-friendly export   |

---

## 🧑‍💻 Installation

1. Make sure you're using **Burp Suite 2025.4.5** (or later) with **Jython 2.7.3**.
2. Download or clone this repository.
3. In Burp:
   - Go to **Extender > Options > Python Environment**.
   - Set the Python path to your `jython-standalone-2.7.3.jar`.
   - Go to **Extender > Extensions**, click **Add**.
     - Extension type: **Python**
     - Extension file: `URL_Collector.py`
4. Once loaded, a new tab will appear: **URL Collector**.

---

## 📋 Usage

- Let Burp capture traffic as usual.
- Enable/disable **Auto-Logging** using the toggle button.
- For any out-of-scope requests you'd like to include:
  - Right-click the request → **Send to URL Collector**
- Copy entries to clipboard using the **Copy** button in the last column.
- Click **Clear Table** to reset the UI.

---

## 🧩 Future Enhancements (Optional Ideas)

- Save/load table to disk
- Search/filter functionality in the table
- CSV/Excel export
- Integrations with Autorize or custom scanner tools
- Capturing of other HTTP methods such as PUT/DELETE.

---

## 👨‍🔬 Author

Built with ❤️ for manual testers and bug bounty hunters who want to organize in-scope URLs quickly and efficiently. Logs Saved, Tested and Autorize columns are added as a part of my customization.
If you do not want to use the Logs Saved, Tested, and Autorize columns in the extension table, you can safely remove them by editing the code:

**Update Column Headers**
In the createUI() or column declaration section, change:

self.columns = ["Domain", "Path", "Method", "No. of Params", "Logs Saved", "Tested", "Autorize", "Copy"]
to:

self.columns = ["Domain", "Path", "Method", "No. of Params", "Copy"]
**Update Row Data**
In the addToTable() or addRequestToTable() method, change:

row = [domain, path, method, str(num_params), "Yes", "", "Yes", "Copy"]
to:

row = [domain, path, method, str(num_params), "Copy"]
**Adjust Copy Button Logic**
Anywhere the code checks if the "Copy" column was clicked:

if column == 7:
should be updated to:

if column == 4:
These columns are optional for logging and tracking, so feel free to tailor the extension for your workflow.

------------------------------------------------------------------------------------
