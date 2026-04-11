import time
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console
from rich.text import Text

console = Console()


def truncate_text(text, max_length):
    """Safely truncate text to a maximum length."""
    if not text:
        return ""
    try:
        text = str(text)
        if len(text) > max_length:
            return text[:max_length - 3] + "..."
        return text
    except Exception:
        return ""


class Dashboard:
    """
    Optimized dashboard for high-volume scanning.
    
    Designed to handle 15000+ requests without UI crashes by:
    - Rate limiting UI updates
    - Capping log/vuln storage
    - Using efficient counters instead of arrays for metrics
    - Robust error handling throughout
    """
    
    def __init__(self):
        # Logs and findings - with strict limits
        self.logs = []
        self.vulns = []
        self.max_logs = 30  # Reduced from 50
        self.max_vulns = 100  # Cap vulnerabilities stored
        
        # Status tracking
        self.current_phase = "Initializing"
        self.current_action = "Ready"
        self.status_message = ""
        self.start_time = None
        self.total_scanners = 0
        self.completed_scanners = 0
        self.animation_frame = 0
        
        # Network metrics - use simple counters, not arrays
        self.active_requests = 0
        self.total_requests = 0
        self.failed_requests = 0
        
        # Rate limiting for updates
        self._last_log_time = 0
        self._log_throttle_ms = 50  # Minimum ms between log additions
        self._skipped_logs = 0
        
        # Error tracking
        self._layout_errors = 0
        self._max_layout_errors = 5
        
        self._init_layout()

    def _init_layout(self):
        """Initialize or recreate the layout structure."""
        try:
            self.layout = Layout()
            self.layout.split_column(
                Layout(name="header", size=3),
                Layout(name="body", ratio=1),
                Layout(name="network", size=3),
                Layout(name="footer", size=3)
            )
            self.layout["body"].split_row(
                Layout(name="logs", ratio=1),
                Layout(name="findings", ratio=1)
            )
        except Exception:
            # Fallback to simple layout
            self.layout = Layout()

    def set_scanner_count(self, count):
        try:
            self.total_scanners = int(count)
        except (ValueError, TypeError):
            self.total_scanners = 0

    def start_timer(self):
        self.start_time = time.time()

    def get_elapsed_time(self):
        if not self.start_time:
            return 0
        try:
            return time.time() - self.start_time
        except Exception:
            return 0

    def net_request_start(self, url):
        """Track request start - lightweight operation."""
        try:
            self.active_requests += 1
            self.total_requests += 1
        except Exception:
            pass

    def net_request_end(self, data):
        """Track request end - lightweight operation."""
        try:
            self.active_requests = max(0, self.active_requests - 1)
        except Exception:
            pass

    def net_request_error(self, data):
        """Track request error - lightweight operation."""
        try:
            self.active_requests = max(0, self.active_requests - 1)
            self.failed_requests += 1
        except Exception:
            pass

    def add_log(self, message):
        """Add a log message with throttling and proper truncation."""
        try:
            # Rate limiting - skip logs if too frequent
            current_time = time.time() * 1000
            if current_time - self._last_log_time < self._log_throttle_ms:
                self._skipped_logs += 1
                # Only skip non-important logs
                if "[P1]" not in str(message) and "[Error]" not in str(message):
                    return
            self._last_log_time = current_time
            
            # Truncate long messages
            message = truncate_text(message, 120)
            
            # Remove problematic control characters
            message = ''.join(c for c in str(message) if c.isprintable() or c in '\n\r\t')
            
            # Parse phase/status updates
            if "[Phase]" in message:
                parts = message.split("]", 1)
                if len(parts) > 1:
                    self.current_phase = truncate_text(parts[1].strip(), 50)
            elif "[Status]" in message:
                parts = message.split("]", 1)
                if len(parts) > 1:
                    self.current_action = truncate_text(parts[1].strip(), 60)

            if "] Scan complete" in message:
                self.completed_scanners += 1

            # Add to logs with cap
            self.logs.append(message)
            while len(self.logs) > self.max_logs:
                self.logs.pop(0)
                
        except Exception:
            pass  # Never crash on logging

    def add_vuln(self, data):
        """Add a vulnerability with error handling."""
        try:
            if not isinstance(data, dict):
                return
                
            vuln_type = truncate_text(data.get('type', 'Unknown'), 40)
            self.add_log(f"[Debug] Vulnerability found: {vuln_type}")
            
            # Cap stored vulnerabilities to prevent memory issues
            if len(self.vulns) < self.max_vulns:
                self.vulns.append(data)
            else:
                # Keep only recent vulns, prioritize P1/P2
                severity = data.get('severity', 'P4')
                if severity in ['P1', 'P2']:
                    # Remove oldest P4, add new critical
                    for i, v in enumerate(self.vulns):
                        if v.get('severity') == 'P4':
                            self.vulns.pop(i)
                            self.vulns.append(data)
                            break
        except Exception as e:
            pass  # Never crash on vuln add

    def generate_layout(self):
        """Generate the dashboard layout with robust error handling."""
        try:
            self.animation_frame = (self.animation_frame + 1) % 10
            spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            spinner = spinner_chars[self.animation_frame]

            status_color = "cyan"
            if "Vulnerability Scanning" in self.current_phase:
                status_color = "red"
            elif "Reporting" in self.current_phase:
                status_color = "green"

            # Header - with error handling
            try:
                header_content = f"[bold {status_color}]{spinner} {truncate_text(self.current_phase, 60)}[/bold {status_color}]"
                self.layout["header"].update(Panel(
                    header_content, 
                    title="[bold white]Lynx v1.0 [BETA] - Active Scan[/bold white]", 
                    border_style=status_color
                ))
            except Exception:
                pass

            # Logs panel - optimized for performance
            try:
                log_lines = []
                visible_logs = self.logs[-12:]  # Reduced from 15
                for log in visible_logs:
                    log = truncate_text(log, 80)  # Reduced from 100
                    if "[Phase]" in log:
                        log_lines.append(f"[bold cyan]{log}[/bold cyan]")
                    elif "[Error]" in log:
                        log_lines.append(f"[bold red]{log}[/bold red]")
                    elif "[P1]" in log:
                        log_lines.append(f"[bold red]{log}[/bold red]")
                    elif "[P2]" in log:
                        log_lines.append(f"[bold orange1]{log}[/bold orange1]")
                    else:
                        log_lines.append(log)

                log_text = "\n".join(log_lines) if log_lines else "[dim]Waiting for logs...[/dim]"
                self.layout["logs"].update(Panel(
                    log_text, 
                    title="Logs", 
                    border_style="blue"
                ))
            except Exception:
                pass

            # Vulnerabilities panel - optimized
            try:
                vuln_lines = []
                for v in self.vulns[-6:]:  # Reduced from 8
                    severity = v.get('severity', 'P4')
                    color = "cyan"
                    icon = "[i]"
                    if severity == "P1":
                        color = "red"
                        icon = "[!]"
                    elif severity == "P2":
                        color = "orange1"
                        icon = "[!!]"
                    elif severity == "P3":
                        color = "yellow"
                        icon = "[~]"

                    vuln_type = truncate_text(v.get('type', 'Unknown'), 25)
                    vuln_str = f"[{color}]{icon} {vuln_type}[/{color}]"
                    
                    url = v.get('url', '')
                    if url:
                        url = truncate_text(url, 35)
                        vuln_str += f"\n  [dim]{url}[/dim]"
                    vuln_lines.append(vuln_str)

                vuln_text = "\n\n".join(vuln_lines) if vuln_lines else "[dim]No vulnerabilities yet...[/dim]"
                self.layout["findings"].update(Panel(
                    vuln_text, 
                    title="Vulnerabilities", 
                    border_style="red"
                ))
            except Exception:
                pass

            # Network monitor - format large numbers nicely
            try:
                total_reqs = self.total_requests
                if total_reqs >= 1000:
                    total_str = f"{total_reqs/1000:.1f}K"
                else:
                    total_str = str(total_reqs)
                    
                failed_reqs = self.failed_requests
                if failed_reqs >= 1000:
                    failed_str = f"{failed_reqs/1000:.1f}K"
                else:
                    failed_str = str(failed_reqs)
                
                net_text = f"Active: [bold cyan]{self.active_requests}[/bold cyan] | Total: [bold white]{total_str}[/bold white] | Failed: [bold red]{failed_str}[/bold red]"
                self.layout["network"].update(Panel(
                    net_text, 
                    title="Network", 
                    border_style="magenta"
                ))
            except Exception:
                pass

            # Footer statistics
            try:
                p1 = sum(1 for v in self.vulns if v.get('severity') == 'P1')
                p2 = sum(1 for v in self.vulns if v.get('severity') == 'P2')
                p3 = sum(1 for v in self.vulns if v.get('severity') == 'P3')
                p4 = sum(1 for v in self.vulns if v.get('severity') == 'P4')

                status_bits = []
                if self.current_action:
                    status_bits.append(f"Action: {truncate_text(self.current_action, 30)}")
                if self.status_message:
                    status_bits.append(truncate_text(self.status_message, 70))

                status_line = " | ".join(status_bits)
                if status_line:
                    status_line = f"\n[dim]{status_line}[/dim]"

                stats = f"[bold red]P1: {p1}[/bold red] | [bold orange1]P2: {p2}[/bold orange1] | [bold yellow]P3: {p3}[/bold yellow] | [bold cyan]P4: {p4}[/bold cyan] | Total: {len(self.vulns)}{status_line}"
                self.layout["footer"].update(Panel(stats, title="Statistics"))
            except Exception:
                pass

            self._layout_errors = 0  # Reset error count on success
            return self.layout
            
        except Exception as e:
            self._layout_errors += 1
            # If too many errors, recreate layout
            if self._layout_errors >= self._max_layout_errors:
                self._init_layout()
                self._layout_errors = 0
            return self.layout


dashboard = Dashboard()

