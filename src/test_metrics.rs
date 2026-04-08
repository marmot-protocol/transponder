#![cfg(test)]

use crate::metrics::Metrics;
use prometheus::proto::{Metric, MetricFamily};

fn metric_matches_labels(metric: &Metric, labels: &[(&str, &str)]) -> bool {
    labels.iter().all(|(name, value)| {
        metric
            .get_label()
            .iter()
            .any(|label| label.name() == *name && label.value() == *value)
    })
}

fn family(metrics: &Metrics, name: &str) -> MetricFamily {
    metrics
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .unwrap_or_else(|| panic!("metric family {name} not found"))
}

fn metric<'a>(family: &'a MetricFamily, labels: &[(&str, &str)]) -> Option<&'a Metric> {
    family
        .get_metric()
        .iter()
        .find(|metric| metric_matches_labels(metric, labels))
}

pub(crate) fn counter_value(metrics: &Metrics, name: &str, labels: &[(&str, &str)]) -> f64 {
    metric(&family(metrics, name), labels)
        .and_then(|metric| metric.get_counter().value)
        .unwrap_or_default()
}

pub(crate) fn gauge_value(metrics: &Metrics, name: &str, labels: &[(&str, &str)]) -> f64 {
    metric(&family(metrics, name), labels)
        .and_then(|metric| metric.get_gauge().value)
        .unwrap_or_default()
}

pub(crate) fn histogram_sample_count(
    metrics: &Metrics,
    name: &str,
    labels: &[(&str, &str)],
) -> u64 {
    metric(&family(metrics, name), labels)
        .and_then(|metric| metric.get_histogram().sample_count)
        .unwrap_or_default()
}

pub(crate) fn histogram_sample_sum(metrics: &Metrics, name: &str, labels: &[(&str, &str)]) -> f64 {
    metric(&family(metrics, name), labels)
        .and_then(|metric| metric.get_histogram().sample_sum)
        .unwrap_or_default()
}
