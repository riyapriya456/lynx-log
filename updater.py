import os
import subprocess
from common import console

def check_for_updates(repo_url="https://github.com/riyapriya456/lynx-log", branch="jules", force=False):
    """
    Checks for updates from the remote git repository.
    """
    console.print("[bold cyan]Checking for updates...[/bold cyan]")

    try:
        # Check if git is installed
        try:
            result = subprocess.run(["git", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if result.returncode != 0:
                console.print("[yellow]Git is not installed. Skipping update check.[/yellow]")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            console.print("[yellow]Git is not installed. Skipping update check.[/yellow]")
            return False

        # Check if inside a git repo
        result = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode != 0:
             console.print("[yellow]Auto-update unavailable: Not a git repository.[/yellow]")
             console.print("[dim]Please clone the repository using git to enable updates:\n  git clone https://github.com/riyapriya456/lynx-log[/dim]")
             return False

        # Fetch latest changes
        console.print(f"[dim]Fetching updates from {branch}...[/dim]")
        subprocess.run(["git", "fetch", "origin", branch], check=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)

        # Get local and remote HEAD hashes
        local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], timeout=10).decode().strip()
        remote_hash = subprocess.check_output(["git", "rev-parse", f"origin/{branch}"], timeout=10).decode().strip()

        if local_hash != remote_hash:
            console.print(f"[bold green]Update available![/bold green] (Local: {local_hash[:7]} -> Remote: {remote_hash[:7]})")
            if force:
                try:
                    from rich.prompt import Confirm
                    if not Confirm.ask("Do you want to update now?"):
                        return False
                except Exception:
                    return False
            
            console.print("[bold cyan]Updating...[/bold cyan]")
            try:
                subprocess.run(["git", "pull", "origin", branch, "--rebase"], check=True, timeout=60)
            except subprocess.CalledProcessError:
                console.print("[yellow]Rebase failed, trying normal pull...[/yellow]")
                try:
                    subprocess.run(["git", "pull", "origin", branch], check=True, timeout=60)
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Update failed: {e}[/red]")
                    return False

            console.print("[bold green]Update successful! Please restart the tool.[/bold green]")
            return True
        else:
            console.print("[bold green]Lynx is up to date.[/bold green]\n")
            return False

    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to check for updates: {e}[/red]")
        return False
    except subprocess.TimeoutExpired:
        console.print("[yellow]Update check timed out. Skipping.[/yellow]")
        return False
    except Exception as e:
        console.print(f"[red]An error occurred during update check: {e}[/red]")
        return False
