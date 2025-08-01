# Session Replacer Burp Extension

A Burp Suite extension written in **Python (Jython 2.7.3)** that allows users to dynamically replace headers and parameters in HTTP requests for all in-scope targets across Burp tools.

# Necessity

Even though we know that burpsuite offers various options for session management such as macros and session management rules, we know that in certain instances they are not handy. So the Session Replacer is a simplified solution that tackles the application behaviour and helps perform the scans and pentesting easier.

## 🧩 Features

* Adds a custom tab named **`Session_replacer`** in Burp.
* GUI is split horizontally into:
  > Header Replacer** section
  > Parameter Replacer** section
* Each section provides **4 editable rows** with two input fields (name and value).
* A single **Replace** button at the bottom applies all configured replacements.
* Automatically modifies matching headers and parameters in requests sent via:

  * Repeater
  * Intruder
  * Scanner
  * Proxy (if request is in scope)

## ⚙️ Requirements

* Burp Suite 2025.4.5 or later
* Jython 2.7.3
* Extension type: Python

## 📦 Installation

1. Go to **Extender → Options → Python Environment**, and set your path to `jython-standalone-2.7.3.jar`.
2. In **Extender → Extensions**, click **Add**:

   * Extension type: Python
   * Select the extension `.py` file
3. A new tab labeled `Session_replacer` will appear.

## 🚀 Usage

1. In the `Session_replacer` tab:

   * Enter the **header name** and **value** you want to override in the top panel.
   * Enter the **parameter name** and **value** in the bottom panel.
   * Leave unused rows blank.
2. Click the **Replace** button.
3. All future *in-scope* requests through Burp tools will have matching headers and parameters replaced.

### 🧪 Example

**Input:**

* Header: `Cookie → sessionid=abc123xyz`
* Param: `_csrf → testvalue123`

**Original Request Body:**

```
username=admin&_csrf=oldtoken&branch=main
```

**Modified Request Body:**

```
username=admin&_csrf=testvalue123&branch=main
```

## 📝 Notes

* Parameter replacement uses regex and works regardless of the request content-type.
* Replacements apply only to *in-scope* requests.
* If a header or parameter name is not found in the request, no change is made.

## 🤝 Credits

Built using Burp Extender API and tested on Burp Suite Professional 2025.4.5 with Jython 2.7.3.
