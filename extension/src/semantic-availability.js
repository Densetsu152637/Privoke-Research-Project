const SEMANTIC_LAYER = "DETECTION_LAYER_SEMANTIC";
const HEALTH_CACHE_MS = 5_000;

export class SemanticAvailability {
  constructor(checkHealth, now = () => Date.now()) {
    this.checkHealth = checkHealth;
    this.now = now;
    this.checkedAt = Number.NEGATIVE_INFINITY;
    this.available = null;
    this.pendingTransition = null;
    this.checkInFlight = null;
  }

  async selectLayers(configuredLayers) {
    if (!configuredLayers.includes(SEMANTIC_LAYER)) {
      return {
        layers: configuredLayers,
        unavailable: false,
        transition: null,
        fallbackLayers: [],
        failClosedOnly: false,
      };
    }

    await this.#refreshIfNeeded();
    const transition = this.pendingTransition;
    this.pendingTransition = null;
    const unavailable = this.available === false;
    const fallbackLayers = configuredLayers.filter((layer) => layer !== SEMANTIC_LAYER);

    // If semantic is the only selected protection, keep it in the request so a
    // streaming failure retains the runtime's existing fail-closed behavior.
    const layers = unavailable && fallbackLayers.length > 0
      ? fallbackLayers
      : configuredLayers;
    return {
      layers,
      unavailable,
      transition,
      fallbackLayers: unavailable ? fallbackLayers : [],
      failClosedOnly: unavailable && fallbackLayers.length === 0,
    };
  }

  async #refreshIfNeeded() {
    if (this.now() - this.checkedAt < HEALTH_CACHE_MS) return;
    if (!this.checkInFlight) {
      this.checkInFlight = Promise.resolve()
        .then(() => this.checkHealth())
        .then((health) => Boolean(health?.ok))
        .catch(() => false)
        .then((available) => {
          if (this.available !== available) {
            this.pendingTransition = available ? "available" : "unavailable";
          }
          this.available = available;
          this.checkedAt = this.now();
        })
        .finally(() => {
          this.checkInFlight = null;
        });
    }
    await this.checkInFlight;
  }
}
