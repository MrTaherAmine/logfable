# Kubernetes service-account compromise and cluster discovery

A synthetic Kubernetes service account is used outside its normal workload context and performs represented cluster discovery without issuing real API requests.

## Environment
Synthetic organization: Northstar Example Cooperative.

## Questions
1. Which identities and assets form the earliest correlated suspicious chain?
2. Which telemetry sources provide the strongest causal evidence?
3. Which benign lookalike could cause an overly broad detection to fire?
4. What visibility gap would most change confidence in the investigation?
