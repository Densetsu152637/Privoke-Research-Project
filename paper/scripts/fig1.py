import matplotlib.pyplot as plt
import numpy as np

def fig1():
    month_labels = [
        "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]
    
    # Time range 
    continuity = 500
    time = np.linspace(0, len(month_labels), continuity)

    # Parameters
    initial_accuracy = 0.50  # starting detection accuracy
    max_accuracy     = 0.95  # plateau / upper limit
    growth_rate      = 0.60  # higher = faster plateau

    # Logarithmic plateau function
    accuracy = max_accuracy - (
        (max_accuracy - initial_accuracy)
        * np.exp(-growth_rate * time)
    )

    # Month labels
    month_positions = np.arange(0, len(month_labels))

    # Smooth line
    plt.figure(figsize=(10, 5))
    plt.plot(
        time,
        accuracy,
        linewidth=2,
        label='Expected Detection Accuracy'
    )
    
    # Optional monthly markers
    monthly_accuracy = max_accuracy - (
        (max_accuracy - initial_accuracy)
        * np.exp(-growth_rate * month_positions)
    )

    plt.scatter(month_positions, monthly_accuracy)

    # Labels and formatting
    plt.title("Expected Detection Accuracy Over Time")
    plt.xlabel("Month")
    plt.ylabel("Detection Accuracy")

    plt.xticks(month_positions, month_labels)
    plt.ylim(0, 1)

    # Labels for monthly points
    for x, y in zip(month_positions, monthly_accuracy):
        plt.text(x, y + 0.015, f"{y:.2f}", ha="center")\
            
    plt.ylim(0, 1)
    plt.grid(True, alpha=0.3)
    plt.legend()

    plt.show()


if __name__ == "__main__":
    fig1()