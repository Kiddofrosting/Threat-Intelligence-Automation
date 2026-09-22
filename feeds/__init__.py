"""Threat-intelligence feed clients. Each feed exposes a small, uniform
interface: query(indicator, ioc_type) -> FeedResult, with its own
on-disk JSON cache and its own failure handling so one dead API never
takes the others down with it.
"""
