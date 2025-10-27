// ============================================================================
// Configuration Constants
// ============================================================================

const CONFIG = {
  SPEED: 0.5,
  FPS: 60,
  MARGIN: 10,
  STAR_COLOR: "#dddddd",
  STAR_SIZE: 4,
  STAR_SIZE_GAIN: 0.8,
  STAR_QTY_GAIN: 2.5,
  // Star generation constants
  STAR_RANDOM_RANGE: 10000,
  STAR_CENTER: 50,
  Z_INITIAL_RANGE: 100,
  Z_INITIAL_OFFSET: -65,
  Z_RESET_RANGE: -100,
} as const;

// ============================================================================
// Type Definitions
// ============================================================================

interface Position {
  x: number;
  y: number;
  z: number;
}

// ============================================================================
// Classes
// ============================================================================

/**
 * Manages a collection of star objects
 */
class StarField {
  private readonly stars: Star[] = [];
  private readonly size: number;

  constructor(size: number) {
    this.size = size;
    for (let i = 0; i < this.size; i++) {
      this.stars.push(new Star());
    }
  }

  getSize(): number {
    return this.size;
  }

  moveStar(index: number): void {
    if (index >= 0 && index < this.size) {
      this.stars[index].move();
    }
  }

  getStarX(index: number, width: number): number {
    if (index >= 0 && index < this.size) {
      return Math.round(this.stars[index].getX() * width);
    }
    return -1000;
  }

  getStarY(index: number, height: number): number {
    if (index >= 0 && index < this.size) {
      return Math.round(this.stars[index].getY() * height);
    }
    return -1000;
  }

  getStarZ(index: number): number {
    if (index >= 0 && index < this.size) {
      return Math.round(this.stars[index].getZ());
    }
    return -1000;
  }
}

/**
 * Represents a single star in the starfield
 */
class Star {
  private x: number = 0;
  private y: number = 0;
  private z: number = 0;
  private readonly xyGain: number = 0.65 * CONFIG.SPEED;
  private readonly zIncrement: number = CONFIG.STAR_SIZE_GAIN * CONFIG.SPEED;

  constructor() {
    this.reset();
    this.z = Math.round(Math.random() * CONFIG.Z_INITIAL_RANGE + CONFIG.Z_INITIAL_OFFSET);
  }

  getLocation(): Position {
    return { x: this.getX(), y: this.getY(), z: this.getZ() };
  }

  getX(): number {
    return this.x / 100;
  }

  getY(): number {
    return this.y / 100;
  }

  getZ(): number {
    return Math.max(0, this.z);
  }

  move(): void {
    this.x += ((this.x - CONFIG.STAR_CENTER) / CONFIG.STAR_CENTER) * this.xyGain;
    this.y += ((this.y - CONFIG.STAR_CENTER) / CONFIG.STAR_CENTER) * this.xyGain;
    this.z += this.zIncrement;

    // Reset star if it moves outside the viewport
    if (this.isOutOfBounds()) {
      this.reset();
      this.z = Math.round(Math.random() * CONFIG.Z_RESET_RANGE);
    }
  }

  private reset(): void {
    this.x = Math.round(Math.random() * CONFIG.STAR_RANDOM_RANGE) / 100;
    this.y = Math.round(Math.random() * CONFIG.STAR_RANDOM_RANGE) / 100;
  }

  private isOutOfBounds(): boolean {
    const maxBound = 100 + CONFIG.MARGIN;
    const minBound = 0 - CONFIG.MARGIN;
    return (
      this.y > maxBound ||
      this.y < minBound ||
      this.x > maxBound ||
      this.x < minBound
    );
  }
}




// ============================================================================
// Rendering & Animation Functions
// ============================================================================

/**
 * Renders the starfield to the canvas
 */
function render(canvas: HTMLCanvasElement, starfield: StarField): void {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  ctx.clearRect(0, 0, canvas.width, canvas.height);

  for (let i = 0; i < starfield.getSize(); i++) {
    const z = (starfield.getStarZ(i) / 100) * CONFIG.STAR_SIZE;
    const x = starfield.getStarX(i, canvas.width) - z / 2;
    const y = starfield.getStarY(i, canvas.height) - z / 2;

    ctx.beginPath();
    ctx.fillStyle = CONFIG.STAR_COLOR;
    ctx.fillRect(x, y, z, z);
    ctx.stroke();

    starfield.moveStar(i);
  }
}


/**
 * Schedules the next animation frame with FPS throttling
 */
function scheduleNextFrame(
  canvas: HTMLCanvasElement,
  starfield: StarField
): void {
  const frameDelay = 1000 / CONFIG.FPS;
  setTimeout(
    () => {
      render(canvas, starfield);
      window.requestAnimationFrame(() => scheduleNextFrame(canvas, starfield));
    },
    frameDelay
  );
}




// ============================================================================
// Initialization
// ============================================================================

const container = document.getElementById("starfield") as HTMLCanvasElement;
let starfield: StarField;

/**
 * Updates canvas dimensions to match viewport
 */
function updateCanvasDimensions(canvas: HTMLCanvasElement): void {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
}

window.addEventListener("load", () => {
  if (!container) return;

  updateCanvasDimensions(container);
  const starCount = Math.round(
    container.width * container.height * 0.0005 * CONFIG.STAR_QTY_GAIN
  );
  starfield = new StarField(starCount);
  scheduleNextFrame(container, starfield);
});

window.addEventListener("resize", () => {
  if (container) {
    updateCanvasDimensions(container);
  }
});