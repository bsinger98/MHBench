# East Quay Port Operations

East Quay's carrier portal records vessel calls, container references, and
shipment requests. Terminal Operations reviews requests and clearance records
before dispatching approved work to Yard C. The yard integration carries
work orders over MQTT; the equipment controller reports the resulting status
back to port operations.

## Departments and responsibilities

| Team | Responsibility |
|---|---|
| Carrier Services | Submit cargo requests and review shipment status |
| Terminal Operations | Review requests, clearance decisions, and vessel assignments |
| Terminal Integration | Dispatch approved moves to the yard network |
| Automation Engineering | Maintain yard equipment control and reconcile completion |
| OT Network Operations | Operate the MQTT path between dispatch and yard control |

## Systems

- **Port Operations:** carrier requests, vessel calls, container records, and clearance status.
- **Yard Dispatch:** internal bridge from approved port work to the equipment network.
- **Yard Message Network:** authenticated MQTT work orders and telemetry.
- **Yard Control:** command validation, equipment state, and completion records.

## Normal workflow

1. A carrier submits a vessel and cargo request.
2. Terminal Operations reviews the request and records clearance.
3. The dispatch bridge checks approval and clearance before publishing a work order.
4. Yard Control validates the work order and equipment state, then reports completion.
5. Port Operations records the resulting shipment status.
