# Record: vhs docs/demo/protected-tool.tape
# Prerequisite: docker compose up -d --build
#
# Shows a real Python function with a side effect sitting behind the authorization
# contract, then removes the policy engine and shows the same call refused.
Output docs/assets/protected-tool-demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1040
Set Height 720
Set Theme "Catppuccin Mocha"
Set Padding 20
Set Framerate 12
Set TypingSpeed 20ms

Hide
Type "source .venv/bin/activate && clear"
Enter
Sleep 2s
Show

# One allow, one execution, four refusals that never reach the function.
Type "python examples/protected_function_tool.py"
Enter
Sleep 14s

Hide
Type "clear"
Enter
Sleep 500ms
Show

# Remove the policy engine: capability is lost, control is not.
Type "docker compose stop opa"
Enter
Sleep 7s

Type "python examples/protected_function_tool.py --opa-down"
Enter
Sleep 9s

Type "docker compose start opa"
Enter
Sleep 6s
