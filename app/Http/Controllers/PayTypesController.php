<?php
namespace App\Http\Controllers;
use App\Models\Pay_Types;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
class PayTypesController extends Controller
{
    public function index()
    {
        try {
            // Intenta obtener todos los registros de Pay_Types
            $payTypes = Pay_Types::all();

            // Retorna una respuesta JSON con los datos obtenidos si tiene éxito
            return response()->json([
                'status' => true,
                'data' => $payTypes,
            ], 200);
        } catch (\Throwable $th) {
            // Maneja cualquier excepción lanzada durante la ejecución
            return response()->json([
                'status' => false,
                'message' => $th  // Devuelve el mensaje de error
            ], 500);
        }
    }
    public function store(Request $request)
    {
        // Define las reglas de validación para los datos de entrada
        $rules = [
            'pay_typ_name' => 'required|string|unique:pay_types|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
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
            // Si la validación pasa, crea una nueva instancia de Pay_Types con los datos del request
            $payType = new Pay_Types($request->input());
            $payType->save();  // Guarda el nuevo registro en la base de datos

            // Llama a un método estático 'NewRegisterTrigger' del controlador base (Controller) para registrar la acción
            Controller::NewRegisterTrigger("Se realizó una inserción de datos en la tabla Pay Types", 3, $request->use_id);

            // Retorna una respuesta JSON indicando el éxito de la operación
            return response()->json([
                'status' => true,
                'message' => "The pay type '" . $payType->pay_typ_name . "' has been added successfully."
            ], 200);
        }
    }
     public function show($id)
    {
        // Busca un registro específico de Pay_Types por su ID
        $payType = Pay_Types::find($id);

        // Si el registro no existe, devuelve un mensaje de error
        if ($payType == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find the Pay Type you are looking for']
            ], 400);
        } else {
            // Si encuentra el registro, devuelve los datos en formato JSON
            return response()->json([
                'status' => true,
                'data' => $payType
            ], 200);
        }
    }
   public function update(Request $request, $id)
    {
        // Busca el registro de Pay_Types que se quiere actualizar por su ID
        $payType = Pay_Types::find($id);

        // Si no encuentra el registro, devuelve un mensaje de error
        if ($payType == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'Could not find required pay type']
            ]);
        } else {
            // Define las reglas de validación para los datos de actualización
            $rules = [
                'pay_typ_name' => 'required|string|regex:/^[A-ZÑÁÉÍÓÚÜ ]+$/u',
                'use_id' => 'required|integer|exists:users'
            ];

            // Ejecuta la validación utilizando el Validator de Laravel
            $validator = Validator::make($request->input(), $rules);

            // Verifica si el nuevo nombre (pay_typ_name) ya existe en otros registros, excluyendo el registro actual
            $validate = Controller::validate_exists($request->pay_typ_name, 'pay_types', 'pay_typ_name', 'pay_typ_id', $id);

            // Si la validación falla o el nombre ya existe en otros registros, devuelve un mensaje de error
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "Value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => false,
                    'message' => $msg
                ]);
            } else {
                // Si la validación pasa y no hay problemas de duplicación, actualiza los datos del registro
                $payType->pay_typ_name = $request->pay_typ_name;
                $payType->save();  // Guarda los cambios en la base de datos

                // Llama al método estático 'NewRegisterTrigger' del controlador base (Controller) para registrar la acción
                Controller::NewRegisterTrigger("Se realizó una actualización de datos en la tabla pay types", 3, $request->use_id);

                // Retorna una respuesta JSON indicando el éxito de la operación
                return response()->json([
                    'status' => true,
                    'message' => "The pay type with ID: " . $payType->pay_typ_id . " has been updated to '" . $payType->pay_typ_name . "' successfully."
                ], 200);
            }
        }
    }
    public function destroy()
    {
        // Este método actualmente devuelve una respuesta JSON estática indicando que el usuario no tiene permiso para eliminar registros
        return response()->json([
            'status' => false,
            'message' => "You have no permission to delete this"
        ], 400);
    }
}
