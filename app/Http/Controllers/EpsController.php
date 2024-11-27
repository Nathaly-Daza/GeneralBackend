<?php

namespace App\Http\Controllers;

use App\Models\Eps;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
class EpsController extends Controller
{
    public function index()
    {
        try {

            // Obtener todas las EPS
            $eps = Eps::all();

            // Devolver una respuesta JSON con las EPS
            return response()->json([
                'status' => true,
                'data' => $eps
            ],200);
        } catch (\Throwable $th) {

            // Manejar la excepción y devolver un mensaje de error
            return response()->json([
               'status' => false,
              'message' => "Error in index, not found elements"
            ],500);
        }
    }
    public function store(Request $request)
    {
        // Reglas de validación para los datos de las EPS
        $rules = [
            'eps_name' => 'required|string|min:1|unique:eps|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s.]+$/',
            'use_id' =>'required|integer|exists:users'
        ];

        // Realizar la validación de los datos recibidos
        $validator = Validator::make($request->input(), $rules);

        // Si la validación falla, devolver los errores
        if ($validator->fails()) {
            return response()->json([
                'status' => False,
                'message' => $validator->errors()->all()
            ]);
        }else{

            // Crear una nueva EPS
            $eps = new Eps($request->input());
            $eps->save();

             // Disparar un nuevo registro
            Controller::NewRegisterTrigger("Se creo un registro en la tabla EPS : $request->eps_name ",3,$request->use_id);

            // Devolver una respuesta JSON de éxito
            return response()->json([
                'status' => True,
                'message' => "The eps: ".$eps->eps_name." has been created."
            ],200);
        }
    }
    public function show($id)
    {

        // Buscar una EPS por su ID
        $eps = Eps::find($id);

        // Si la EPS no se encuentra, devolver un mensaje de error
        if ($eps == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The eps requested was not found.']
            ],400);
        }else{

            // Devolver la EPS encontrada
            return response()->json([
                'status' => true,
                'data' => $eps
            ]);
        }
    }
    public function update(Request $request, $id)
    {

        // Buscar una EPS por su ID
        $eps = Eps::find($id);

        // Si la EPS no se encuentra, devolver un mensaje de error
        if ($eps == null) {
            return response()->json([
                'status' => false,
                'data' => ['message' => 'The eps requested was not found']
            ],400);
        }else{

            // Reglas de validación para actualizar los datos de la EPS
            $rules = [
                'eps_name' => 'required|string|min:1|max:255|regex:/^[A-ZÑÁÉÍÓÚÜ\s.]+$/',
                'use_id' =>'required|integer|exists:users'
            ];

            // Realizar la validación de los datos recibidos
            $validator = Validator::make($request->input(), $rules);

            // Validar que no exista otra EPS con el mismo nombre
            $validate = Controller::validate_exists($request->eps_name, 'eps', 'eps_name', 'eps_id', $id);

            // Si la validación falla o ya existe otra EPS con el mismo nombre, devolver los errores
            if ($validator->fails() || $validate == 0) {
                $msg = ($validate == 0) ? "value tried to register, it is already registered." : $validator->errors()->all();
                return response()->json([
                    'status' => False,
                    'message' => $msg
                ]);
            }else{

                // Actualizar los datos de la EPS
                $eps->eps_name = $request->eps_name;
                $eps->save();

                // Disparar un nuevo registro
                Controller::NewRegisterTrigger("Se realizo una Edicion de datos en la tabla EPS del dato: $id con el dato: $request->eps_name",1,$request->use_id);

                // Devolver una respuesta JSON de éxito
                return response()->json([
                    'status' => True,
                    'message' => "The eps: ".$eps->eps_name." has been update."
                ],200);
            }
        }
    }
    public function destroy()
    {

        // Devolver un mensaje indicando que esta función no está disponible
        return response()->json([
            'status' => false,
            'message' => "FUNCTION NOT AVAILABLE"
        ],400);
    }
}
