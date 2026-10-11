"""Viewer key/button release logic, run in node against a stub DOM."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

HTML = (Path(__file__).parent.parent / "loom_computer" / "viewer.html").read_text()
SCRIPT = re.search(r"<script>(.*)</script>", HTML, re.S).group(1)

HARNESS = r"""
const sent = [], handlers = {};
function target(name) {
  return { addEventListener(t, fn) { handlers[name + ':' + t] = fn; },
    getContext() { return {}; }, focus() {}, setPointerCapture() {}, width: 1280, height: 800,
    getBoundingClientRect() { return { left: 0, top: 0, width: 1280, height: 800 }; },
    textContent: '' };
}
const canvas = target('canvas'), win = target('window'), doc = target('document');
doc.getElementById = (id) => (id === 'screen' ? canvas : target(id));
doc.hidden = false;
global.document = doc; global.window = win;
global.location = { hash: '#tok', protocol: 'http:', host: 'h' };
global.WebSocket = function () { this.readyState = 1; this.send = (m) => sent.push(JSON.parse(m)); };
global.WebSocket.OPEN = 1;
(0, eval)(process.argv[1]);
const key = (type, k, meta) => handlers['canvas:' + type]({ key: k, metaKey: !!meta, preventDefault() {} });
SCENARIO
console.log(JSON.stringify(sent));
"""


def run(scenario: str):
    out = subprocess.run(["node", "-e", HARNESS.replace("SCENARIO", scenario), SCRIPT],
                         capture_output=True, text=True, check=True).stdout
    return [(m["t"], m.get("key"), m.get("down"), m.get("buttons")) for m in json.loads(out)]


def test_blur_releases_held_keys_and_buttons():
    sent = run("""
      key('keydown', 'a'); key('keydown', 'Shift');
      handlers['canvas:pointerdown']({ clientX: 5, clientY: 6, buttons: 1, pointerId: 1 });
      handlers['window:blur']();
    """)
    assert ("key", "a", False, None) in sent and ("key", "Shift", False, None) in sent
    assert sent[-1] == ("pointer", None, None, 0)


def test_release_during_meta_is_not_swallowed():
    sent = run("""
      key('keydown', 'c'); key('keydown', 'Meta');
      key('keyup', 'c', true);
    """)
    assert ("key", "c", False, None) in sent


def test_meta_release_lets_go_of_keys_whose_keyup_was_dropped():
    sent = run("""
      key('keydown', 'Meta'); key('keydown', 'x'); key('keydown', 'k');
      key('keyup', 'Meta', false);
    """)
    assert ("key", "Meta", False, None) in sent


def test_unheld_release_sends_nothing():
    assert run("key('keyup', 'z', true);") == []
