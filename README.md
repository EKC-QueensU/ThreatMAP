# ThreatMAP: Mapping Attack Plans from the Techniques, Tactics and Procedures of the MITRE ATT&CK Enterprise Framework for Plan Recognition

In this research the application of plan recognition is applied in the cybersecurity domain for the detection of anomalous behaviours indicative of cyber kill chains occuring on enterprise Information Technology (IT) networks.Cyberattacks are becoming much more frequent on enterprise networks. As the kill chains developed for cyberattacks become increasingly sophisticated, they become more and more difficult to detect, and are only alerted upon after an cyberattack has occurred. The cyber threat landscape is ever evolving and there exists a multitude of combinations of techniques and tactics that can be used to develop a cyberattack, increasing the need for automating the detection of the kill chains outlined by the Mitre Attack Enterprise Matrix. The tactics and techniques of the MITRE ATT\&CK Enterprise Frameworks allows for the unification of network and host-based alerting, providing greater visibility on the network. By modeling the cyber kill chain it is possible to match the actions of an attacker before the network is compromised.

## Submission

This is our project submission for the Fall 2023 semester of CISC813. 

The following files are our final submission for our CISC813 course project: 
- CISC813_Project_ThreatMAP_Final_ECoote_TPerkins: Final paper
- finaldomain.pddl: Final domain file to be considered
- finalproblem.pddl: Final problem file to be considered
- Kill Chain Policies
- - sas_plan.1 : Policy resultant of kill chain 1 (Ferocious Kitten)
  - sas_plan.2 : Policy resultant of kill chain 2 (APT29)
  - sas_plan.3 : Policy resultant of kill chain 3 (APT29)
  - sas_plan.4 : Policy resultant of kill chain 4 (Axiom)
  - sas_plan.5 : Policy resultant of kill chain 5 (Metador)

 The domain and project files were tested and working in the planutils enviroment. 
 
  The following files were part of the draft submission:
  - CISC_813_Project_ThreatMAP_ECoote__TPerkins.pdf
  - projectdomain.pddl
  - projectproblem.pddl

## How to run: 

1. In the finalproblem.pddl there are 5 kill chains described. Uncomment one of the kill chains
2. In the planutils environment run: lama finaldomain.pddl finalproblem.pddl

This domain can be further expanded on by adding more entities and building other kill chains for detection. 
