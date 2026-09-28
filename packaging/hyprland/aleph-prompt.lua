-- aleph's unlock prompt (alephd starts it as `aleph-gui prompt`): float it
-- in the middle of the screen, on every workspace, and keep the keyboard on
-- it while it is open, so a password is never typed into another window.
-- (It closes itself: answered, cancelled with Escape, timed out, or, for a
-- closing message, after 20 seconds.)
-- `alephctl setup` offers to include this from ~/.config/hypr/hyprland.lua.
hl.window_rule({
  match = { class = "^aleph-prompt$" },
  float = true,
  center = true,
  pin = true,
  stay_focused = true,
})
