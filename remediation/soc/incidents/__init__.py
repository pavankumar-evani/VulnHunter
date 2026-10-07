"""
SOC incident automation: alerts are grouped into incidents, given a summary and a kill-chain view, and routed to an analyst or a tier queue without anyone
creating a case. See docs/SOC_INCIDENTS.md. An incident is the unit of work; the existing soc_cases row it is routed as carries its service-level clocks.
"""
