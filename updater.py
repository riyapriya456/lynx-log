import os
import subprocess
from rich.prompt import Confirm
from common import console

def check_for_updates(repo_url="https://github.com/riyapriya456/lynx-log", branch="jules"):
    """
    Checks for updates from the remote git repository.
    """
    console.print("[bold cyan]Checking for updates...[/bold cyan]")

    try:
        # Check if git is installed
        if subprocess.call(["git", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            console.print("[yellow]Git is not installed. Skipping update check.[/yellow]")
            return

        # Check if inside a git repo
        if subprocess.call(["git", "rev-parse", "--is-inside-work-tree"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
             console.print("[yellow]Not a git repository. Skipping update check.[/yellow]")
             return

        # Fetch latest changes
        console.print(f"[dim]Fetching updates from {branch}...[/dim]")
        subprocess.run(["git", "fetch", "origin", branch], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        # Get local and remote HEAD hashes
        local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
        remote_hash = subprocess.check_output(["git", "rev-parse", f"origin/{branch}"]).decode().strip()

        if local_hash != remote_hash:
            console.print(f"[bold green]Update available![/bold green] (Local: {local_hash[:7]} -> Remote: {remote_hash[:7]})")
            if Confirm.ask("Do you want to update now?"):
                console.print("[bold cyan]Updating...[/bold cyan]")
                subprocess.run(["git", "pull", "origin", branch], check=True)
                console.print("[bold green]Update successful! Please restart the tool.[/bold green]")
                os._exit(0)
        else:
            console.print("[bold green]Lynx is up to date.[/bold green]\n")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to check for updates: {e}[/red]")
    except Exception as e:
        console.print(f"[red]An error occurred during update check: {e}[/red]")
