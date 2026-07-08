# Record: vhs docs/demo/asg-demo.tape
# Prerequisite: docker compose up -d --build (ASG_DEMO_MODE=true)
Output docs/assets/asg-demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 620
Set Theme "Catppuccin Mocha"
Set Padding 20
Set Framerate 12

Type "export ASG_URL=http://localhost:8000"
Enter
Sleep 400ms
Type "./scripts/record_demo_gif.sh"
Enter
Sleep 24s
