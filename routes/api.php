<?php

use App\Http\Controllers\AccessController;
use App\Http\Controllers\ActivityController;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\AreaController;
use App\Http\Controllers\CareerController;
use App\Http\Controllers\CareerTypesController;
use App\Http\Controllers\CivilStatesController;
use App\Http\Controllers\CoformationProcessTypesController;
use App\Http\Controllers\ContactCompaniesTypesController;
use App\Http\Controllers\ContactController;
use App\Http\Controllers\Controller;
use App\Http\Controllers\CoreMaterialController;
use App\Http\Controllers\CountryController;
use App\Http\Controllers\CovenantTypesController;
use App\Http\Controllers\DiseasesController;
use App\Http\Controllers\DocTypesController;
use App\Http\Controllers\EpsController;
use App\Http\Controllers\GenderController;
use App\Http\Controllers\HistoryCarrerController;
use App\Http\Controllers\HistoryPromotionController;
use App\Http\Controllers\HistoryScholarshipsController;
use App\Http\Controllers\IndustryController;
use App\Http\Controllers\LearningObjectsController;
use App\Http\Controllers\LocalityController;
use App\Http\Controllers\MailsController;
use App\Http\Controllers\MedicalhistoriesController;
use App\Http\Controllers\MonetaryStateController;
use App\Http\Controllers\MulticulturalismsController;
use App\Http\Controllers\NewsController;
use App\Http\Controllers\NewTypeController;
use App\Http\Controllers\PayTimesController;
use App\Http\Controllers\PayTypesController;
use App\Http\Controllers\PeriodController;
use App\Http\Controllers\PersonController;
use App\Http\Controllers\PhaseController;
use App\Http\Controllers\PositionController;
use App\Http\Controllers\ProjectController;
use App\Http\Controllers\PromotionController;
use App\Http\Controllers\RelationshipsController;
use App\Http\Controllers\ScholarshipsController;
use App\Http\Controllers\StudentController;
use App\Http\Controllers\StudentEnrollmentsController;
use App\Http\Controllers\StudentTypeController;
use App\Http\Controllers\TelephonesController;
use App\Http\Controllers\VinculationTypeController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
Route::post('/register/{use_id}', [AuthController::class, 'register'])->name('register');
Route::post('/login/{proj_id}', [AuthController::class, 'login'])->name('login');
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');
Route::post('reset/password', [PersonController::class, 'reset_password'])->name('reset.password');
Route::post('send/email/', [PersonController::class, 'sendEmailReminder'])->name('send.email');
Route::post('password/emergency', [PersonController::class, 'passwordEmergency'])->name('password.emergency');
Route::get('profile/{proj_id}/{use_id}', [PersonController::class, 'profile'])->name('profile');
Route::get('Unauthenticated', [Controller::class, 'Unauthenticated'])->name('Unauthenticated');
Route::fallback(function () {
    return response()->json([
        'message' => 'The route you are looking for does not exist.'
    ], 404);
});

//===============NO QUITAR EL MIDDLEWARE================================
Route::middleware(['auth:sanctum'])->group(function() {
    Route::resource('access', AccessController::class)->names('access')->parameter('','access');
    Route::resource('activity', ActivityController::class)->names('activity')->parameter('','activity');
    Route::resource('areas', AreaController::class)->names('areas')->parameter('','areas');
    Route::resource('career', CareerController::class)->names('career')->parameter('','career');
    Route::resource('careers/types', CareerTypesController::class)->names('career.types')->parameter('','career_types');
    Route::resource('civil/states', CivilStatesController::class)->names('civil.states')->parameter('','civil_states');
    Route::resource('coformation/process/types', CoformationProcessTypesController::class)->names('coformation.process.types')->parameter('','coformation_process_types');
    Route::resource('contact/companies/type', ContactCompaniesTypesController::class)->names('contact.companies.types')->parameter('','contact_companies_types');
    Route::resource('contacts', ContactController::class)->names('contacts')->parameter('','contacts');
    Route::resource('covenant/types', CovenantTypesController::class)->names('covenant.types')->parameter('','covenant_types');
    Route::resource('country', CountryController::class)->names('country')->parameter('','country');
    Route::resource('diseases', DiseasesController::class)->names('diseases')->parameter('','diseases');
    Route::resource('doc/types', DocTypesController::class)->names('doc.types')->parameter('','doc_types');
    Route::resource('eps', EpsController::class)->names('eps')->parameter('','eps');
    Route::resource('genders', GenderController::class)->names('genders')->parameter('','genders');
    Route::resource('history/promotion', HistoryPromotionController::class)->names('history.promotion')->parameter('','history_promotion');
    Route::resource('history/careers', HistoryCarrerController::class)->names('')->parameter('','history_career');
    Route::resource('industry', IndustryController::class)->names('industry')->parameter('','industry');
    Route::resource('localities', LocalityController::class)->names('localities')->parameter('','localities');
    Route::resource('mails', MailsController::class)->names('mails')->parameter('','mails');
    Route::resource('medical/histories', MedicalhistoriesController::class)->names('medical.histories')->parameter('','medical_histories');
    Route::resource('monetary/states', MonetaryStateController::class)->names('monetary.states')->parameter('','money_states');
    Route::resource('multiculturalisms', MulticulturalismsController::class)->names('multiculturalisms')->parameter('','multiculturalisms');
    Route::get('news', [NewsController::class, 'index'])->name('news.index');
    Route::get('news/{type}/{proj_id}/{date}', [NewsController::class, 'show'])->name('news.show');
    Route::resource('new/types', NewTypeController::class)->names('new.types')->parameter('','new_types');
    Route::resource('pay/times', PayTimesController::class)->names('pay.times')->parameter('','pay_times');
    Route::resource('pay/types', PayTypesController::class)->names('pay.types')->parameter('','pay_types');
    Route::resource('period', PeriodController::class)->names('period')->parameter('','period');
    Route::resource('persons', PersonController::class)->names('persons')->parameter('','persons');
    Route::post('persons/document', [PersonController::class, 'viewForDocument'])->name('view.for.document');
    Route::put('update/personal/information', [PersonController::class, 'updateCoforInformation'])->name('update.cofor.information');
    Route::post('persons/documentStudent', [StudentController::class, 'viewForDocumentStudent'])->name('view.for.document');
    Route::get('persons/filtred'.'{column}/{data}', [PersonController::class, 'filtredfortypeperson'])->name('filtrar.personas');
    Route::post('prueba', [AuthController::class, 'uploadFile'])->name('upload.persons');
    Route::post('update/password/{proj_id}/{use_id}', [PersonController::class, 'update_password'])->name('update.password');
    Route::post('update/photo/{id}', [PersonController::class, 'updatePhoto'])->name('update.photo');
    Route::get('persons/filtred/{id}/{docTypeId}', [PersonController::class, 'filtredforDocument'])->name('filtredforDocument');
    Route::get('last/persons', [PersonController::class, 'lastPersons'])->name('last.persons');
    Route::resource('phase', PhaseController::class)->names('phase')->parameter('','phase');
    Route::resource('positions', PositionController::class)->names('positions')->parameter('','positions');
    Route::resource('projects', ProjectController::class)->names('projects')->parameter('','projects');
    Route::resource('promotion', PromotionController::class)->names('promotion')->parameter('','promotion');
    Route::resource('relationships', RelationshipsController::class)->names('relationships')->parameter('','relationships');
    Route::resource('scholarships', ScholarshipsController::class)->names('scholarships')->parameter('','scholarships');
    Route::resource('history/scholarships', HistoryScholarshipsController::class)->names('history.scholarships')->parameter('','history_scholarships');
    Route::resource('learning/objects', LearningObjectsController::class)->names('learning.objects')->parameter('', 'learning_objects');
    Route::resource('core/materials', CoreMaterialController::class)->names('core.materials')->parameter('', 'core_materials');
    Route::resource('student/types', StudentTypeController::class)->names('student.types')->parameter('','student_types');
    Route::resource('student', StudentController::class)->names('student')->parameter('','student');
    Route::apiResource('students/enrollments',StudentEnrollmentsController::class)->names('student.enrollments')->parameter('', 'student_enrollments');
    Route::get('students', [StudentController::class, 'indexAmount'])->name('filtrar.personas');
    Route::get('history/enrollments', [StudentEnrollmentsController::class, 'historyEnrollments']);
    Route::resource('telephones', TelephonesController::class)->names('telephones')->parameter('','telephones');
    Route::resource('vinculation/type', VinculationTypeController::class)->names('vinculation.type')->parameter('','vinculation_type');

});
