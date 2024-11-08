package runner

import "github.com/chris-cmsoft/concom/runner/proto"

type CallableEvalResponse struct {
	*proto.EvalResponse
}

func NewCallableEvalResponse() *CallableEvalResponse {
	return &CallableEvalResponse{
		EvalResponse: &proto.EvalResponse{
			Status:       proto.ExecutionStatus_SUCCESS,
			Observations: []*proto.Observation{},
			Findings:     []*proto.Finding{},
		},
	}
}

func (eval *CallableEvalResponse) AddObservation(observation *proto.Observation) {
	eval.Observations = append(eval.Observations, observation)
}

func (eval *CallableEvalResponse) AddFinding(finding *proto.Finding) {
	eval.Findings = append(eval.Findings, finding)
}

func (eval *CallableEvalResponse) Result() *proto.EvalResponse {
	return eval.EvalResponse
}
