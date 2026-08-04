# Worker controller

Each enabled worker is managed by one controller actor. The actor is the only
component allowed to move that worker between lifecycle states or publish it
to the dispatcher.

Startup is fail-closed:

1. create the namespace and veth;
2. install bootstrap default-drop rules;
3. start the OpenVPN supervisor;
4. wait for process, tunnel, and route readiness;
5. install active rules;
6. start the namespace worker process;
7. make a real public-IP request through that proxy;
8. apply expected-IP, host-leak, and uniqueness policy;
9. atomically publish the worker as healthy.

Failure handling first marks the dispatcher entry unhealthy and closes sessions
for the worker ID. It then installs strict firewall mode before stopping or
restarting processes. A failure to install strict mode is fatal to that worker;
shutdown still attempts strict mode and namespace deletion.

The OpenVPN service adapter converts the existing process/tunnel supervisor
events into controller readiness and failure events. A controller-requested
restart cancels the entire supervised OpenVPN generation, so readiness from a
previous public-IP verification is never retained.

The daemon builder creates one actor per enabled configuration after every
profile has been inspected, resolved, and safely derived. The runtime applies
the shared host firewall before opening the dispatcher, starts the actors
concurrently, and cancels and joins them before removing the host table.
