import numpy as np
import matplotlib.pyplot as plt

def fig2():

    month_labels = [
        "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]

    # Continuous time range
    time = np.linspace(0, len(month_labels), 500)

    # Runtime speed parameters
    initial_speed = 12.0     # starts high
    min_speed = 6.0          # plateaus lower
    decay_rate = 0.20

    # Smooth decreasing curve
    speed = min_speed + (
        (initial_speed - min_speed)
        * np.exp(-decay_rate * time)
    )

    # Add realistic noise
    np.random.seed(42)
    noise = np.random.normal(0, 0.1, len(time))

    # Reduce noise over time for stabilisation effect
    noise *= np.exp(-0.08 * time)

    speed_noisy = speed + noise

    # Month labels
    month_positions = np.arange(0, len(month_labels))

    # Plot
    plt.figure(figsize=(10, 5))

    plt.plot(
        time,
        speed_noisy,
        linewidth=2.2,
        label="Runtime Speed"
    )

    # Monthly markers
    monthly_speed = min_speed + (
        (initial_speed - min_speed)
        * np.exp(-decay_rate * month_positions)
    )

    plt.scatter(month_positions, monthly_speed)

    # Labels for monthly points
    for x, y in zip(month_positions, monthly_speed):
        plt.text(x, y + 0.25, f"{y:.1f}", ha="center")

    plt.title("Runtime Speed Over Time")
    plt.xlabel("Month")
    plt.ylabel("Runtime Speed (Abstract Units)")

    plt.xticks(month_positions, month_labels)

    plt.grid(True, alpha=0.3)
    plt.legend()

    plt.show()
    
if __name__ == "__main__":
    fig2()