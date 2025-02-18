#!/bin/sh
#!/bin/bash

mv /app/gobgpd_$MODE.yml /app/gobgpd.yml

/app/gobgpd -f /app/gobgpd.yml --log-level=debug &
/app/router -mode $MODE
