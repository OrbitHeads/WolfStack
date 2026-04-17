# Card View for LXC, Docker, VM Screens

## Summary

Add a card/grid view as an alternative to the current table view on the LXC containers, Docker containers, and VM management screens. Users can toggle between card and table view, and the preference is saved in localStorage.

## Design

### Card Layout
- 4 cards across on desktop (grid: repeat(4, 1fr))
- 2 cards on tablet, 1 on mobile
- Each card shows: name, status (running/stopped badge), key metrics (CPU, RAM, disk), action buttons (start/stop/restart/delete/console)
- Cards have a colored left border: green=running, red=stopped, yellow=paused
- Click card → opens detail view (same as clicking table row currently)

### Toggle
- Small icon toggle (grid icon / list icon) in the header next to the search bar
- Saved to `localStorage.setItem('wolfstack_view_docker', 'card')` etc.
- Three keys: `wolfstack_view_docker`, `wolfstack_view_lxc`, `wolfstack_view_vms`
- Default: table (current behavior unchanged)

### Card Content per Type

**Docker:**
- Container name + image
- Status badge (running/stopped/paused)
- Ports (if exposed)
- CPU/RAM usage bar (if running)
- Buttons: Start/Stop, Restart, Logs, Console, Delete

**LXC:**
- Container name
- Status badge
- IP address
- CPU/RAM/Disk usage
- Buttons: Start/Stop, Restart, Console, Delete

**VM:**
- VM name
- Status badge (running/stopped)
- CPUs, RAM, Disk size
- VNC button (if running)
- Buttons: Start/Stop, Settings, VNC, Delete

## Implementation

### Files to modify:
- `web/js/app.js` — three sections: loadDockerContainers, loadLxcContainers, loadVms
- Each needs: toggle button in header, card renderer, localStorage read/write

### Approach:
1. Add `renderViewToggle(storageKey)` function that returns the toggle HTML
2. Add `renderCards(items, type)` function that renders the grid
3. In each load function, check localStorage and render either table or cards
4. Toggle button switches view and re-renders

## NOT starting yet — just planning.
