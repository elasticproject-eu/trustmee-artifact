wit_bindgen::generate!({
    path: "wit",
    world: "verifier",
});

struct Component;

impl exports::trustee::verifier::verifier_interface::Guest for Component {
    type Verifier = Verifier;
}

struct Verifier;

impl exports::trustee::verifier::verifier_interface::GuestVerifier for Verifier {
    fn new() -> Self {
        Self
    }

    fn evaluate(
        &self,
        _input: exports::trustee::verifier::verifier_interface::VerifierInput,
        _expected_report_data: exports::trustee::verifier::verifier_interface::OptionalData,
        _expected_init_data_hash: exports::trustee::verifier::verifier_interface::OptionalData,
    ) -> String {
        loop {}
    }
}

export!(Component);
