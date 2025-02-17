#!/bin/sh
#!/bin/bash

mv /app/gobgpd_$MODE.yml /app/gobgpd.yml

/app/gobgpd -f /app/gobgpd.yml &
/app/router -mode $MODE
