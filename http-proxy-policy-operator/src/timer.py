# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Systemd timer."""

import logging
import pathlib

from charms.operator_libs_linux.v1 import systemd

logger = logging.getLogger(__name__)

DISPATCH_EVENT_SERVICE = """\
[Unit]
Description=Dispatch the {event} event on {unit}
[Service]
Type=oneshot
ExecStart=/usr/bin/timeout {timeout} /usr/bin/bash \\
 -c '/usr/bin/juju-exec "{unit}" "JUJU_DISPATCH_PATH={event} ./dispatch"'
[Install]
WantedBy=multi-user.target
"""

SYSTEMD_SERVICE_TIMER = """\
[Unit]
Description=Run {service} repeatedly
Requires={service}.service
[Timer]
Unit={service}.service
OnBootSec=300
OnUnitInactiveSec={interval}
RandomizedDelaySec=5
Persistent=true
[Install]
WantedBy=timers.target
"""


def start_timer(unit_name: str, event_name: str, timeout: int, interval: int) -> None:
    """Install a timer.

    Args:
        unit_name: Unit name where to start the timer
        event_name: The event to be fired
        timeout: timeout in seconds before killing the command
        interval: interval in seconds between each execution
    """
    (pathlib.Path("/etc/systemd/system/") / f"dispatch-{event_name}.service").write_text(
        DISPATCH_EVENT_SERVICE.format(
            event=event_name,
            timeout=timeout,
            unit=unit_name,
        ),
        encoding="utf-8",
    )
    (pathlib.Path("/etc/systemd/system/") / f"dispatch-{event_name}.timer").write_text(
        SYSTEMD_SERVICE_TIMER.format(interval=interval, service=f"dispatch-{event_name}"),
        encoding="utf-8",
    )
    systemd.service_enable(f"dispatch-{event_name}.timer")
    systemd.service_start(f"dispatch-{event_name}.timer")
