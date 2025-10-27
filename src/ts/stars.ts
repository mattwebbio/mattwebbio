// Configurables
let SPEED: number = 1,
    FPS: number = 30,
    MARGIN: number = 10,
    STAR_COLOR: string = "#dddddd",
    STAR_SIZE: number = 4,
    STAR_SIZE_GAIN: number = 0.8,
    STAR_QTY_GAIN: number = 2.5;






// Classes
class stars {
    private starray: Array<star> = [];
    private size: number;

    constructor(size: number) {
        this.size = size;
        for (let i = 0; i < this.size; i++){
            this.starray.push(new star());
        }
    }

    getSize(): number {
        return this.size;
    }

    moveStar(i: number): void {
        if (i > this.getSize() || i < 0) return;
        else this.starray[i].move();
    }

    getStarX(i: number, width: number): number {
        if (i > this.getSize() || i < 0) return -1000;
        else return Math.round(this.starray[i].getX() * width);
    }

    getStarY(i: number, height: number): number {
        if (i > this.getSize() || i < 0) return -1000;
        else return Math.round(this.starray[i].getY() * height);
    }

    getStarZ(i: number): number {
        if (i > this.getSize() || i < 0) return -1000;
        else return Math.round(this.starray[i].getZ());
    }
}

class star {
    private x: number = 0;
    private y: number = 0;
    private z: number = 0;
    private XY_GAIN: number = 0.65 * SPEED;
    private Z_INCREMENT: number = STAR_SIZE_GAIN * SPEED;
    private MARGIN: number = MARGIN;

    constructor() {
        this.reset();
        this.z = Math.round((Math.random() * 100) - 65);
    }
    getLoc(): Array<number> {
        return [this.getX(), this.getY(), this.getZ()];
    }
    getX(): number {
        return this.x/100;
    }
    getY(): number {
        return this.y/100;
    }
    getZ(): number {
        if (this.z < 0) return 0;
        else return this.z;
    }
    reset(): void {
        this.x = Math.round(Math.random() * 10000)/100;
        this.y = Math.round(Math.random() * 10000)/100;
    }
    move(): void {
        this.x += ((this.x - 50)/50)*this.XY_GAIN;
        this.y += ((this.y - 50)/50)*this.XY_GAIN;
        this.z += this.Z_INCREMENT;

        if (this.y > (100 + this.MARGIN) || this.y < (0 - this.MARGIN) || 
        this.x > (100 + this.MARGIN) || this.x < (0 - this.MARGIN)){
            this.reset();
            this.z = Math.round(Math.random() * -100);
        }
    }
}






// Functions
function render(container: HTMLCanvasElement, starfield: stars): void {
    const canvas = container.getContext("2d");
    if (!canvas) return;

    canvas.clearRect(0, 0, container.width, container.height);

    for (let i = 0; i < starfield.getSize(); i++){
        let z = starfield.getStarZ(i)/100 * STAR_SIZE,
            x = starfield.getStarX(i, container.width) - (z/2),
            y = starfield.getStarY(i, container.height) - (z/2);

        canvas.beginPath();
        canvas.fillStyle=STAR_COLOR;
        canvas.fillRect(x, y, z, z);
        canvas.stroke();

        starfield.moveStar(i);
    }
}

function fitCanvas(): void {
    // Match viewport size since canvas is fixed to the viewport
    container.style.height = window.innerHeight + "px";
    container.width  = container.offsetWidth;
    container.height = container.offsetHeight;
}

function nextFrame() {
    render(container, starfield);
    return setTimeout(function(){window.requestAnimationFrame(nextFrame)}, 1000/FPS);
}






// Main
const container = document.getElementById("starfield") as HTMLCanvasElement;
let starfield: stars;

window.onload = function() {
    if (!container) return;

    fitCanvas();
    starfield = new stars(Math.round((container.width*container.height)
        *0.0005*STAR_QTY_GAIN));
    window.requestAnimationFrame(nextFrame);
}

window.onresize = function() {
    fitCanvas();
}