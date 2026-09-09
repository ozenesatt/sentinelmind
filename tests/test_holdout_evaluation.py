from eval.evaluate_holdout import calculate_metrics


def test_holdout_metric_calculation():
    rows = [
        {
            "expected_positive": True,
            "predicted_positive": True,
        },
        {
            "expected_positive": True,
            "predicted_positive": False,
        },
        {
            "expected_positive": False,
            "predicted_positive": True,
        },
        {
            "expected_positive": False,
            "predicted_positive": False,
        },
    ]

    metrics = calculate_metrics(rows)

    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tn"] == 1

    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5

    print("Holdout metric calculation BASARILI")


if __name__ == "__main__":
    test_holdout_metric_calculation()