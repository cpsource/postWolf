Overview: This readme discusses tools available for parsing config files. We dive in a bit
with Argus.

Question: What tools are available for parsing config files?

Yes — there are a few good options, depending on how “formal” your /etc/config file is.

👍 1. Built-in:
configparser (if your file is INI-like)
If your file looks like this:

[section]
key1 = value1
key2 = value2
then Python already has a standard library:

👉 configparser

Reads INI-style config files
Gives you dictionary-style access
No external dependency
Example:

import configparser

config = configparser.ConfigParser()
config.read('/etc/myconfig.conf')

value = config['section']['key1']
print(value)
This is the most common solution, but it requires sections and key=value syntax.  

👍 2. If your file is just:
key <spaces> value (no sections)
Example:

host localhost
port 8080
debug true
👉 configparser won’t handle this cleanly.

Option A — simplest: use
shlex (very clean)
import shlex

config = {}

with open('/etc/config') as f:
    for line in f:
        parts = shlex.split(line)
        if len(parts) >= 2:
            key = parts[0]
            value = " ".join(parts[1:])
            config[key] = value

print(config['host'])
Why this is nice:

Handles quoted strings correctly
Ignores weird spacing
Very Unix-friendly
Option B — manual parse (fast + explicit)
config = {}

with open('/etc/config') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, value = line.split(None, 1)   # split on whitespace
        config[key] = value

print(config['port'])
👍 3. More advanced: use YAML instead
If you can control the format, switch to YAML:

👉 PyYAML

Example file:

host: localhost
port: 8080
Code:

import yaml

with open('/etc/config.yaml') as f:
    config = yaml.safe_load(f)

print(config['host'])
YAML is more flexible and widely used for configs.  

👍 4. Power-user option: Augeas (for real
/etc/* files)
If you’re dealing with actual Linux system configs (like /etc/ssh/sshd_config, etc.):

👉 Augeas

Parses many real-world config formats
Gives you a structured tree view
Has Python bindings
This is what tools like Puppet/Salt use.  

⚡ Bottom line
INI format? → use configparser
Simple “key value” lines? → use shlex or manual split
Want modern config? → use YAML (PyYAML)
Parsing real /etc/* system configs? → use Augeas
If you want, paste a sample of your actual /etc/config file — I’ll give you a parser tailored exactly to that format.

===

Question: Is augeas on github?

Yes — Augeas is absolutely on GitHub, and it’s actively maintained.

🧰 Augeas (what you’re looking for)
👉 The project is here:

Augeas (GitHub: hercules-team/augeas)
👍 Short answer to your question
Yes:

✔ Open source
✔ On GitHub
✔ Has Python bindings
✔ Designed specifically for /etc/* style config files
⚡ Why Augeas is different (and better for /etc files)
Most Python libraries assume clean formats (INI, JSON, YAML).

But real /etc/config files:

mix comments, whitespace, odd syntax
don’t follow strict standards
must preserve formatting when edited
👉 Augeas solves this with “lenses”:

Parses files into a tree structure
Lets you query/edit safely
Writes back without breaking the file
🧪 Example (Python usage)
import augeas

aug = augeas.Augeas()

# Load file
aug.set("/augeas/load/MyConfig/lens", "Simplevars.lns")
aug.set("/augeas/load/MyConfig/incl", "/etc/config")
aug.load()

# Read value
value = aug.get("/files/etc/config/port")
print(value)
🧠 When you should use Augeas
Use it if:

You’re parsing real Linux config files
You care about not breaking formatting
You want safe edits (not regex hacks)
⚠️ When NOT to use it
Don’t use Augeas if:

Your file is simple (key value) → just use split()
You control the format → use YAML instead
🧩 Reality check
Augeas is powerful, but:

Slightly heavier setup
Requires understanding lenses
Overkill for simple configs
Bottom line
✔ Yes, it’s on GitHub
✔ Yes, it’s the right tool for /etc/* parsing
⚠️ But only if your config is complex enough to justify it
If you paste your actual /etc/config, I’ll tell you whether Augeas is worth it or if you should just write 10 lines of Python and be done.

===

Question: Can you generate a aug file?

Yes. Give me:

# comments?
key   value
key2  value with spaces?
and rules for:

comments:        # or ;
blank lines:     allowed?
separator:       spaces only, or = too?
key chars:       letters/numbers/_/-/. ?
value chars:     anything to end of line?
quotes:          "like this" allowed?
duplicates:      allowed or last one wins?
sections:        any [section] headers?
includes:        include otherfile?
I can produce:

myconfig.aug      # the Augeas lens
test_myconfig.aug # unit tests
Augeas is specifically meant to parse native config files into a tree and write them back safely.  
