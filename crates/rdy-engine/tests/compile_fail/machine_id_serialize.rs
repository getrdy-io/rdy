use rdy_engine::probe::MachineId;

fn write(id: &MachineId) -> String {
    serde_json::to_string(id).unwrap()
}

fn main() {}
