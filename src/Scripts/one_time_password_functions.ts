function toRadians(angle: number){
    return angle * (Math.PI / 180);
}

export function calculate_one_time_password(x: number, name: string){
    let a = name.length;
    let result = (a * Math.sin(toRadians(x))).toPrecision(5);

    console.log(result);
    return result;
}

export function convert_one_time_password(oneTimePassword: string){
    let result = parseFloat(oneTimePassword).toPrecision(5);

    console.log(result);
    return result;
}