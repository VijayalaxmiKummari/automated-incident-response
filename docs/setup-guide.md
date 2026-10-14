# Setup Guide (macOS)

This assumes the [Home SOC Lab](https://github.com/VijayalaxmiKummari/home-soc-lab) is already running in Splunk at `/Applications/Splunk`.

## 1. Get the project

```bash
cd ~
git clone https://github.com/VijayalaxmiKummari/automated-incident-response.git
cd automated-incident-response
```

## 2. Try the demo (no Splunk needed)

```bash
python3 respond.py --demo
```

Then look at what it produced:

```bash
ls output/tickets
cat output/tickets/INC-*-001.md
cat output/blocklist.txt
```

Clear it before running against Splunk:

```bash
python3 respond.py --reset
```

## 3. Make sure the lab has attacks to respond to

```bash
cd ~/home-soc-lab
python3 log-generator/generate_logs.py --attack-now
cd ~/automated-incident-response
```

## 4. Run against Splunk

```bash
python3 respond.py
```

Enter your Splunk admin password when asked (it is not shown as you type). The tool reads the six SOC Lab detections from Splunk, runs them over the last 24 hours, and responds.

Run it a second time: it should say **No new incidents**, because it remembers what it has already handled.

To keep it running and respond to new attacks as they happen:

```bash
python3 respond.py --watch 60
```

Press **Ctrl+C** to stop.

## 5. Send the response actions back into Splunk

```bash
sed "s#/CHANGE/ME#$HOME#" splunk/inputs.conf.example >> /Applications/Splunk/etc/apps/soc_lab/local/inputs.conf
cp splunk/props.conf /Applications/Splunk/etc/apps/soc_lab/local/props.conf
/Applications/Splunk/bin/splunk restart
```

Then in Splunk, search over the last 24 hours:

```spl
index=soc_lab sourcetype=air:actions
| table _time incident_id severity action target result
| sort _time
```

## 6. Screenshots for the README

Save these in the `screenshots/` folder:

| File name | What to capture |
|---|---|
| `responder-run.png` | Terminal output of `python3 respond.py` showing the incidents |
| `ticket.png` | One ticket opened in a text editor or previewed on GitHub |
| `splunk-actions.png` | The `air:actions` search from step 5 |
| `tests.png` | Output of `python3 -m unittest discover tests -v` |

## Troubleshooting

| Message | Fix |
|---|---|
| `Could not reach Splunk` | Start Splunk: `/Applications/Splunk/bin/splunk start` |
| `Splunk rejected the username or password` | Use the admin login you created when installing Splunk |
| `Not found in Splunk ... Home SOC Lab app installed?` | Install the `soc_lab` app from the Home SOC Lab project |
| All detections show `0 result(s)` | Run `generate_logs.py --attack-now` in the Home SOC Lab, then try again |
