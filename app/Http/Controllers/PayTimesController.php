<?php

namespace App\Http\Controllers;

use App\Models\Pay_Times;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;

class PayTimesController extends Controller
{
    public function index()
    {
        try {
            // Intenta obtener todos los registros de Pay_Times
            $paytimes = Pay_Times::all();

            // Retorna una respuesta JSON con los datos obtenidos si tiene éxito
            return response()->json([
                'status' => true,
                'data' => $paytimes,
            ], 200);
        } catch (\Throwable $th) {
            // Maneja cualquier excepción lanzada durante la ejecución
            return response()->json([
                'status' => false,
                'message' => $th // Devuelve el mensaje de error
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Define las reglas de validación para los datos de entrada
        $rules = [
            'pay_tim_name' => 'required|string|unique:pay_times|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
            'use_id' => 'required|integer|exists:users'
        ];

        // Ejecuta la validación utilizando el Validator de Laravel
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devuelve un mensaje de error
        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ]);
        } else {
            // Si la validación pasa, crea una nueva instancia de Pay_Times con los datos del request
            $paytimes = new Pay_Times($request->input());
            $paytimes->save();  // Guarda el nuevo registro en la base de datos

            // Llama a un método estático 'NewRegisterTrigger' del controlador base (Controller) para registrar la acción
            Controller::NewRegisterTrigger("Se realizó una inserción de datos en la tabla Pay Times", 3, $request->use_id);

            // Retorna una respuesta JSON indicando el éxito de la operación
            return response()->json([
                'status' => true,
                'message' => "The pay type '" . $paytimes->pay_tim_name . "' has been added successfully."
            ], 200);
        }
    }
    public function show($id)
    {
        // Busca un registro específico de Pay_Times por su ID
        $paytimes = Pay_Times::find($id);

        // Si el registro no existe, devuelve un mensaje de error
        if ($paytimes == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the Pay Time you are looking for']
            ], 400);
        } else {
            // Si encuentra el registro, devuelve los datos en formato JSON
            return response()->json([
                'status' => true,
                'data' => $paytimes
            ], 200);
        }
    }
    public function update(Request $request, $id)
    {
        // Busca el registro de Pay_Times que se quiere actualizar por su ID
        $paytimes = Pay_Times::find($id);

        // Si no encuentra el registro, devuelve un mensaje de error
        if ($paytimes == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find required pay type']
            ]);
        } else {
            // Define las reglas de validación para los datos de actualización
            $rules = [
                'pay_tim_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
                'use_id' => 'required|integer|exists:users'
            ];

            // Ejecuta la validación utilizando el Validator de Laravel
            $validator = Validator::make($request->input(), $rules);

            // Verifica si el nombre de pay_tim_name ya existe en otros registros, excluyendo el registro actual
            $validate = Controller::validate_exists($request->pay_tim_name, 'pay_times', 'pay_tim_name', 'pay_tim_id', $id);

            // Si la validación falla o el nombre ya existe en otros registros, devuelve un mensaje de error
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "Value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Si la validación pasa y no hay problemas de duplicación, actualiza los datos del registro
                $paytimes->pay_tim_name = $request->pay_tim_name;
                $paytimes->save();  // Guarda los cambios en la base de datos

                // Llama al método estático 'NewRegisterTrigger' del controlador base (Controller) para registrar la acción
                Controller::NewRegisterTrigger("Se realizó una actualización de datos en la tabla pay times", 3, $request->use_id);

                // Retorna una respuesta JSON indicando el éxito de la operación
                return response()->json([
                    'status' => true,
                    'message' => "The pay time with ID: " . $paytimes->pay_tim_id . " has been updated to '" . $paytimes->pay_tim_name . "' successfully."
                ], 200);
            }
        }
    }
    public function destroy($id, $proj_id, $use_id)
    {
        // Este método está actualmente retornando un mensaje de falta de permisos para eliminar registros
        return response()->json([
            'status' => false,
            'message' => "You have no permission to delete this"
        ], 400);
    }
}
